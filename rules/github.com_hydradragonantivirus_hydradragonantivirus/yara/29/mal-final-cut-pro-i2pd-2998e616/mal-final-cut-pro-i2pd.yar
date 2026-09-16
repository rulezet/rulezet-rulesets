rule mal_final_cut_pro_i2pd {
  meta:
    description = "Identify macOS Logic Pro X Cryptocurrency malware's embedded I2P daemon"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.26"
    sample      = "810bb73988dc47558b220047534d6dab9a55632c1defa40a761543ebaaa2f02c"
    reference   = "https://www.jamf.com/blog/cryptojacking-macos-malware-discovered-by-jamf-threat-labs/"
    DaysofYARA  = "57/100"

  strings:
    $s1 = "/Users/user/dev/i2pd/stage-x86_64/lib"
    $s2 = "i2p::"
    $s3 = "pidfile"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}