rule sig_20160517_5fa26bf75c9865995097a953e97ae428 {
  meta:
    description = "datamaliciousorder - file 20160517_5fa26bf75c9865995097a953e97ae428.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea16a02aca871b78eb6d809c4794354d543612595a22da2008a110dd178340f3"

  strings:
    $s1 = "var vrm='vqh1tnaucrnfrpkdgv gzdo3lwxehtkl4ne3faojkiqy4orqfalbbwbytwehmclfcxac31qh=kazlp\\'lms1dtrytoacipxmxnikjoriertgifejmbzutn" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}