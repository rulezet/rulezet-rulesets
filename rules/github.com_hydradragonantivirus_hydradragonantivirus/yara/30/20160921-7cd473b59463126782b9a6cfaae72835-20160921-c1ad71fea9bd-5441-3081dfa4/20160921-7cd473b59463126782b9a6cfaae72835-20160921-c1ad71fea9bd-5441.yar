rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_c1ad71fea9bd_5441 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s2 = "(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s3 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function " ascii
    $s4 = "function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s5 = "n f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}