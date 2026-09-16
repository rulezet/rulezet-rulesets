rule sig_20160526_62562da1bf9b1f418a4ec7c0bda0594f {
  meta:
    description = "datamaliciousorder - file 20160526_62562da1bf9b1f418a4ec7c0bda0594f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afeb8fdca6cc287695948dc57d9a1d216c4ed87c6bf8fff9c742d121448ff5ed"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])x" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "v\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;\"eelS\" = bCCT rav\\n\\r;\"p" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}