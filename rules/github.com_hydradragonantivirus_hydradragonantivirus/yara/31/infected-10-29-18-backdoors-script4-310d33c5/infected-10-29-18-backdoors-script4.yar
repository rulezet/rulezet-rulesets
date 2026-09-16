rule infected_10_29_18_backdoors_script4 {
  meta:
    description = "backdoors - file script4"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-10-28"
    hash1       = "6fabfa701da14a21835c61fb7fdbe4db3341528fbedadb696f2bd48c9569d21f"

  strings:
    $s1 = "eyB2YXIgczE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0IiksczA9ZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoInNjcmlwdCIpWzBdOyBzMS5hc3lu" ascii  
    $s2 = "Yz10cnVlOyBzMS5zcmM9U3RyaW5nLmZyb21DaGFyQ29kZSgxMDQsIDExNiwgMTE2LCAxMTIsIDExNSwgNTgsIDQ3LCA0NywgMTA0LCAxMTEsIDExNiwgMTExLCAxMTIs" ascii  
    $s3 = "IDExMiwgMTExLCAxMTAsIDEwMSwgMTEwLCAxMTYsIDExNSwgNDYsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDcsIDExNSwgMTA1LCAxMTYsIDEwMSwgNDYsIDEwNiwgMTE1" ascii  

  condition:
    (uint16(0) == 0x474a and
      filesize < 6KB and
      (all of them)
    ) or (all of them)
}