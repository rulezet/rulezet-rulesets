rule sig_20160525_793f459fa26c3e834b3d0e843fbd4dfe {
  meta:
    description = "datamaliciousorder - file 20160525_793f459fa26c3e834b3d0e843fbd4dfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4735cb10cb3283c91f857ed98acc2d3ab8215403adfdcb6b24ede6dec8e9f7e"

  strings:
    $s1 = "sillock(mk + suidarelcitrapk[suidarelcitrapb" fullword ascii
    $s2 = " rav\\n;\"56x\\\\jbO56x\\\\\" = keppell rav\\n;\"t36x\\\\\" = ecapsetihwxelfl rav\\n;\"44x\\\\O44x\\\\A\" = modnarl rav\\n;\"47x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}