rule _20160921_b32c8921e3390cb8f9450436f4e43cfb_20160922_433c067ed379_3126 {
  meta:
    description = "datamaliciousorder - from files 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})" ascii
    $s2 = "PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(funct" ascii
    $s3 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s4 = "00(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\"" ascii
    $s5 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s6 = "nction f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){ret" ascii
    $s7 = "0(){return \"TKl\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}