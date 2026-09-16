rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_6bf1e6b71f68_1888 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"

  strings:
    $s1  = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){r" ascii
    $s2  = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s3  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ot\";})(),(function " ascii
    $s4  = " fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py" ascii
    $s5  = "urn \"Wo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s6  = "fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs" ascii
    $s7  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s8  = "urn \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s9  = "ion fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"" ascii
    $s10 = "ction fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}