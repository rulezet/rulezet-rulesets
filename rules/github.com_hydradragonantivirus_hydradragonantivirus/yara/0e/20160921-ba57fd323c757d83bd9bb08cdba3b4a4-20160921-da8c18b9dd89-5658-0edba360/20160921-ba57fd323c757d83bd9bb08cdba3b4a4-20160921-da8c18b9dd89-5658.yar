rule _20160921_ba57fd323c757d83bd9bb08cdba3b4a4_20160921_da8c18b9dd89_5658 {
  meta:
    description = "datamaliciousorder - from files 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash2       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"
    hash3       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1 = "(){return \"ILp\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";}" ascii
    $s2 = "urn \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s3 = "n fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"X" ascii
    $s4 = "return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s5 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}