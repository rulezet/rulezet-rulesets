rule sig_20160525_1a5c675a6f3754d11602677c81fbb2bd {
  meta:
    description = "datamaliciousorder - file 20160525_1a5c675a6f3754d11602677c81fbb2bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "451a00295d021b0a74954f1a329e01b4a3db33767e438c01b5d8be9649ee3d78"

  strings:
    $s1 = "dart rav\\n;\"r16x\\\\86x\\\\C\" = keppelt rav\\n;\"t56x\\\\s\" = ecapsetihwxelft rav\\n;\"07x\\\\o\" = modnart rav\\n;\"n56x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}