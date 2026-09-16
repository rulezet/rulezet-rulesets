rule RAR_Archive_ren: RarLab {
  meta:
    author = "_pusher_"
    date   = "2016-09"

  strings:
        $a0 = { 52 61 72 21 1A 07 (00 | 01) ?? ?? 73 ?? 00 0D 00 00 00 00 00 00 00 }
        $a1 = { 52 61 72 21 1A 07 01 00 ?? ?? ?? ?? ?? 01 05 ?? 00 ?? 01 01 }
    
  condition:
        (
      any of ($a*)
                            )

}