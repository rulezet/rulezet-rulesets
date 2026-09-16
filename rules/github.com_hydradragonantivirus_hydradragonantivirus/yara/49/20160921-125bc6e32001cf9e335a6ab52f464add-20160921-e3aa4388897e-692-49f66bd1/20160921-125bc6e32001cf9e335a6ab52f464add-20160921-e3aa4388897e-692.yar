rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_e3aa4388897e_692 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1  = "Qr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s2  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){retur" ascii
    $s3  = "){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s4  = "k(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s5  = ";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fu" ascii
    $s6  = "urn \"Zy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(f" ascii
    $s7  = "n \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fu" ascii
    $s8  = "unction fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s9  = "\"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s10 = "tion fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s11 = "\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s12 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s13 = "\"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s14 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s15 = "uck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe" ascii
    $s16 = "ck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"EHo" ascii
    $s17 = "rn \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s18 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(function fuck()" ascii
    $s19 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s20 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}