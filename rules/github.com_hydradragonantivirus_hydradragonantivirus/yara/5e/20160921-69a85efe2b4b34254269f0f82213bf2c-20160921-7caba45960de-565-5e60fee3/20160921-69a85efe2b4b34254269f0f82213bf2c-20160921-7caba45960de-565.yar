rule _20160921_69a85efe2b4b34254269f0f82213bf2c_20160921_7caba45960de_565 {
  meta:
    description = "datamaliciousorder - from files 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_7caba45960de8ab0904dc3a8514f2614.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash2       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"

  strings:
    $s1  = ";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuc" ascii
    $s2  = "fuck(){return \"XFd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"I" ascii
    $s3  = "tion fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s4  = "),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){" ascii
    $s5  = "(),(function fuck(){return \"Et\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii
    $s6  = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s7  = ";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s8  = "n \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(func" ascii
    $s9  = "ction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return" ascii
    $s10 = "unction fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){ret" ascii
    $s11 = "ction fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){retur" ascii
    $s12 = "),(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck()" ascii
    $s13 = "rn \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s14 = "})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fu" ascii
    $s15 = "fuck(){return \"CCb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s16 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retu" ascii
    $s17 = "u\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s18 = "l\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s19 = "){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";" ascii
    $s20 = "on fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}