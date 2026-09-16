rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160921_e949fdc198fe_3906 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash3       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s2 = "){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";}" ascii
    $s3 = "000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s4 = ")(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s5 = "urn \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(f" ascii
    $s6 = "\"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}