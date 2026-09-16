rule sig_20160315_746c6651df469afc4479657cb1785212 {
  meta:
    description = "datamaliciousorder - file 20160315_746c6651df469afc4479657cb1785212.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8266d4d4fe30191050f8aefceedeee82ff6791baa6d6f654c451e2ecdee1bafe"

  strings:
    $s1 = "        return WScript[r](a);" fullword ascii
    $s2 = "!function(a) {" fullword ascii
    $s3 = "var venialYEG = function(a) {" fullword ascii
    $s4 = "var preternaturalxw6 = function() {" fullword ascii
    $s5 = "    var Y = String[\"f\" + \"ro\" + \"mC\" + \"ha\" + \"rC\" + \"ode\"];" fullword ascii
    $s6 = "        for (a = 0; a < r; a++) lookup[a] = code[a];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}