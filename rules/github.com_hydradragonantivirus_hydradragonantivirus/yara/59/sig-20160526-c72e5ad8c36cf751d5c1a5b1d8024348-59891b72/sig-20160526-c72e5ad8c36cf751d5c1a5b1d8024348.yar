rule sig_20160526_c72e5ad8c36cf751d5c1a5b1d8024348 {
  meta:
    description = "datamaliciousorder - file 20160526_c72e5ad8c36cf751d5c1a5b1d8024348.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bb497741543bdb759c236852e03bacfa5850ff47bf5d21e04c19ec5e11b8b44"

  strings:
    $s1 = "0mRQCXWA + c8fVPWZQI + )p3mESVTHI(m4sCQYZVX( = o5tHYBRWX rav\\n;\"323x\\\\11\" = p3mESVTHI rav\\n;\"313x\\\\\" = c8fVPWZQI rav" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}