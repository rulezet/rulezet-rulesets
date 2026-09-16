rule sig_20160525_1eee82db61dbe5d6f214f42f444cc805 {
  meta:
    description = "datamaliciousorder - file 20160525_1eee82db61dbe5d6f214f42f444cc805.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a635580886fcef131d28ca9179902a500d7df1db35fdc0beaacc388a5b71d119"

  strings:
    $s1 = "\\\" = modnaru rav\\n;\"86x\\\\t\" = deerdu rav\\n;\"ec6x\\\\\" = sdnetu rav\\n;\"h47x\\\\76x\\\\n\" = ssorcau rav'[\"split\"]('" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}