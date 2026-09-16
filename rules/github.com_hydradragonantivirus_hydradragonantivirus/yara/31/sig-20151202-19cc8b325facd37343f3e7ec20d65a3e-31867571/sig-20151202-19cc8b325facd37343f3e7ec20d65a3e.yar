rule sig_20151202_19cc8b325facd37343f3e7ec20d65a3e {
  meta:
    description = "datamaliciousorder - file 20151202_19cc8b325facd37343f3e7ec20d65a3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57431713bd7e782e006d689ce019c2ce9b3a0db5a8ee2849c051ebecd9c1d807"

  strings:
    $s1 = "function r(cbkumXOnPPOIWpvnkuL){ DrRUPmBK='';for(tsiitLzGZ = 0; tsiitLzGZ < 3; tsiitLzGZ++){DrRUPmBK+=String.fromCharCode(cbkumX" ascii
    $s2 = "OnPPOIWpvnkuL[tsiitLzGZ]);}DrRUPmBK+=String.fromCharCode(cbkumXOnPPOIWpvnkuL[3]);return DrRUPmBK}" fullword ascii
    $s3 = "function r(cbkumXOnPPOIWpvnkuL){ DrRUPmBK='';for(tsiitLzGZ = 0; tsiitLzGZ < 3; tsiitLzGZ++){DrRUPmBK+=String.fromCharCode(cbkumX" ascii
    $s4 = "function CKPbXqQGeXBFtNd(elIZRFCZmezjgDWVFWQDUrimCtqwpg){eval(elIZRFCZmezjgDWVFWQDUrimCtqwpg)};" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}