rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_7cd473b59463_3887 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s3 = "(),(function f000(){return \"Wb\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s5 = "n \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(func" ascii
    $s6 = "(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}