rule mal_macos_silver_sparrow {
  meta:
    description = "Identify macOS SilverSparrow distrubtion scripts."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.24"
    references  = "https://redcanary.com/blog/clipping-silver-sparrows-wings/"
    sample      = "b60f1c6b95b8de397e7d92072412d1970ba474ff168ccabbc641d2a65b307b8a"
    DaysofYARA  = "83/100"

  strings:
    $a0 = {
      48 bf 48 65 6c 6c 6f 2c 20 57        48 be 6f 72 6c 64 21 00 00 ed        e8                                 }
    $a1 = {
      48 bf 59 6f 75 20 64 69 64 20        48 be 69 74 21 00 00 00 00 eb        e8                                 }

    $b0 = "SwiftUI6VStackVMn"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    any of ($a*) and all of ($b*)
}