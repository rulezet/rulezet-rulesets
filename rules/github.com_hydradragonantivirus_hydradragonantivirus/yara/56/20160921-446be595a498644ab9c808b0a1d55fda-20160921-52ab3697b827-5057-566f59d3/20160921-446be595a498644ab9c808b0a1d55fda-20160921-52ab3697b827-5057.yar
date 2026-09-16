rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_52ab3697b827_5057 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash3       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash4       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash5       = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"

  strings:
    $s1 = "){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})" ascii
    $s2 = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){retur" ascii
    $s3 = "})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck" ascii
    $s4 = "urn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(fu" ascii
    $s5 = "uck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}