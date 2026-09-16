rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_69a85efe2b4b_104 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js, 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"
    hash3       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash4       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1  = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return" ascii
    $s2  = "nction fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s4  = "urn \"PDf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5  = ",(function fuck(){return \"Qh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s6  = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(fun" ascii
    $s7  = "{return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s8  = "turn \"Ik\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s9  = "ck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Vb" ascii
    $s10 = "q\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Yk\";})(),(function " ascii
    $s11 = " \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DWe\";})(),(fun" ascii
    $s12 = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retur" ascii
    $s13 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(" ascii
    $s14 = "(function fuck(){return \"XCr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){re" ascii
    $s15 = "turn \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s16 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Mw" ascii
    $s17 = "tion fuck(){return \"Mw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s18 = "urn \"Fv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s19 = "(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s20 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}