rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_8621b60975e0_3543 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"

  strings:
    $s1 = "(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2 = "),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYx\";})(),(function f000()" ascii
    $s3 = "{return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s5 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return " ascii
    $s6 = "{return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}