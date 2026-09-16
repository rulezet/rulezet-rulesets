rule sig_20160525_455e11d7cfd4341e7b026ed3ed1385ff {
  meta:
    description = "datamaliciousorder - file 20160525_455e11d7cfd4341e7b026ed3ed1385ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93a482aa0d277f5d962cda17a2fa2bb1b0c203a45672ed1be74c152213a33a4e"

  strings:
    $s1 = "sillock(mk + suidarelcitrapk[suidarelcitrapb" fullword ascii
    $s2 = " rav\\n;\"56x\\\\jbO56x\\\\\" = keppell rav\\n;\"t36x\\\\\" = ecapsetihwxelfl rav\\n;\"44x\\\\O44x\\\\A\" = modnarl rav\\n;\"47x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}