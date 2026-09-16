rule sig_20160525_feb197ee42dd1a5cff18622bf865828f {
  meta:
    description = "datamaliciousorder - file 20160525_feb197ee42dd1a5cff18622bf865828f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aedd8b15f0e329b6d65a274978439862810a192138d50880c74c7bd40741c3aa"

  strings:
    $s1 = "neti + deerdi[rerednera[rerednera = /*  WVB VVl OcZ */ sdnet rav" fullword ascii
    $s2 = "\\n;\"u17x\\\\\" = cthh rav\\n;\"s56x\\\\\" = rerednerh rav\\n;\"13x\\\\.5.t\" = imh rav;};gsmi nruter{)gsmi(eixodi noitcnuf\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}