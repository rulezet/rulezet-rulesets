rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_b2002e7f99c6_5310 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1 = " \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s2 = "Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s3 = "nction f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s4 = "){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})" ascii
    $s5 = "rn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}