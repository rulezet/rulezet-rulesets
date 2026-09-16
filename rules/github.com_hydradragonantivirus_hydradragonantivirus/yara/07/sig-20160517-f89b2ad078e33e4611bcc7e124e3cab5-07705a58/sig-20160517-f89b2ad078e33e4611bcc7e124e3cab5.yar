rule sig_20160517_f89b2ad078e33e4611bcc7e124e3cab5 {
  meta:
    description = "datamaliciousorder - file 20160517_f89b2ad078e33e4611bcc7e124e3cab5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e97244253a3db48a7f66a78a1d23dd114358031007d132704f0943cb64259d8c"

  strings:
    $s1 = "var tyctbb='vqstliabr1pmrw1d31 jgfcodkzmn3jc3zd4khrvwdknlyeaxfgbti1kptlvnxxuykwqgmwnonzelw=nthk2\\'wziqstgwhoicv1f2ynxyfguir1ubl" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}