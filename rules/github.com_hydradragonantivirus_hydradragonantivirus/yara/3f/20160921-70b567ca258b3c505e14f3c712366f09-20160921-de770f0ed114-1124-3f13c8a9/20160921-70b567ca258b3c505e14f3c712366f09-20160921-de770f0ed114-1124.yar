rule _20160921_70b567ca258b3c505e14f3c712366f09_20160921_de770f0ed114_1124 {
  meta:
    description = "datamaliciousorder - from files 20160921_70b567ca258b3c505e14f3c712366f09.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"
    hash2       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1  = "tion fuck(){return \"GWo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s2  = "unction fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3  = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s4  = " \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s5  = "\"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"SUi\";})(),(func" ascii
    $s6  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s7  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Et\"" ascii
    $s8  = "Pu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s9  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s10 = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s11 = "uck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy" ascii
    $s12 = "){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s13 = "n fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s14 = " fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s15 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s16 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})" ascii
    $s17 = " \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}