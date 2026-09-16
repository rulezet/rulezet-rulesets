rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_19d073f9fafc_2717 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash3       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash4       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash5       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash6       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = ",(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000()" ascii
    $s2 = "(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";}" ascii
    $s3 = " f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OU" ascii
    $s4 = "return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "n f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"G" ascii
    $s6 = "),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){" ascii
    $s7 = "return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}