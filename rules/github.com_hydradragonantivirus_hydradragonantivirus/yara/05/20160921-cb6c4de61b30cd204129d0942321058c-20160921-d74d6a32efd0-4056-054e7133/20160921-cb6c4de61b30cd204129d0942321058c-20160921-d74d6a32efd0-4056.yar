rule _20160921_cb6c4de61b30cd204129d0942321058c_20160921_d74d6a32efd0_4056 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s2 = "(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\"" ascii
    $s3 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s4 = "Ux\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function" ascii
    $s5 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s6 = "{return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}