rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_882f77897bba_4602 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"T" ascii
    $s2 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f" ascii
    $s3 = "){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = ";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii
    $s5 = "(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}