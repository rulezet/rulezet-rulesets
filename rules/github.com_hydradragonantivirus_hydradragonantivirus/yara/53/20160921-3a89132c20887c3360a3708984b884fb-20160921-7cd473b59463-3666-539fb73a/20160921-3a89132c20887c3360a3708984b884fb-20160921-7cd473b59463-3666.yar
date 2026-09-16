rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_7cd473b59463_3666 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";}" ascii
    $s2 = "ction f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){retur" ascii
    $s3 = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f0" ascii
    $s4 = "0(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";" ascii
    $s5 = "ion f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s6 = "{return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}