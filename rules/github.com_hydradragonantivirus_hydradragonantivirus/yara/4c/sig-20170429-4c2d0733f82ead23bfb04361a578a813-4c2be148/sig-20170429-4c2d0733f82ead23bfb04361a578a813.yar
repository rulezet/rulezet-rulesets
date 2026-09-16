rule sig_20170429_4c2d0733f82ead23bfb04361a578a813 {
  meta:
    description = "datamaliciousorder - file 20170429_4c2d0733f82ead23bfb04361a578a813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06747458dd37594e17f938eb5dc2e98516913f86f402182b922e922131ea9f54"

  strings:
    $s1 = "return UhZnxwuGJfDQovpF.split(hjnKzeAYbgwTlqVXN).join(zcRhNsVtmpgCDMfaT); }" fullword ascii
    $s2 = "function GBRLYqIMzfSTJongtc(UhZnxwuGJfDQovpF, hjnKzeAYbgwTlqVXN, zcRhNsVtmpgCDMfaT) { " fullword ascii
    $s3 = "if (CNOmjhUFWVGsqIoplS() == false) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}