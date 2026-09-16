rule sig_20170119_202a6366f7b0c3c3e1233763cc2ac19f {
  meta:
    description = "datamaliciousorder - file 20170119_202a6366f7b0c3c3e1233763cc2ac19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2232bc10a71d59af2c05d7a6d51bf0ac5245fbbaeff2174e504d884873decac"

  strings:
    $s1  = "//var VetpJXCT = new Date();while(true) {var hhcutqT = new Date();var TFGxOAm = new Date(hhcutqT.getTime() - VetpJXCT.getTime())" ascii
    $s2  = "//var VetpJXCT = new Date();while(true) {var hhcutqT = new Date();var TFGxOAm = new Date(hhcutqT.getTime() - VetpJXCT.getTime())" ascii
    $s3  = ";if(TFGxOAm.getSeconds() > 7) {break;}WScript.Sleep(300);}" fullword ascii
    $s4  = "function chgzkpQNbl(hvNEPUjrojD){return hvNEPUjrojD.ExpandEnvironmentStrings('%T'+'MP%');}var hYrPz='UsRKiVQhqaOsRxMmvQfyTvghKVO" ascii
    $s5  = "nction bdayuPpTy(htTJJbjuAC,lmQHXrvEyR){htTJJbjuAC.run(lmQHXrvEyR,0x0+1, 0x0);}function hoIqx(NjHbdc){ return NjHbdc.ExpandEnvir" ascii
    $s6  = "function lKNPZA(yKgoA){var SmhFyXLK = '2'+'8';var RVnuyA='\"' + new Date() + '\"';var ytilcB=0;while(ytilcB<yKgoA.length){var Fe" ascii
    $s7  = "function lKNPZA(yKgoA){var SmhFyXLK = '2'+'8';var RVnuyA='\"' + new Date() + '\"';var ytilcB=0;while(ytilcB<yKgoA.length){var Fe" ascii
    $s8  = "function nkhQvIAEAvrk(ofADNWquUIOM){return chgzkpQNbl(ofADNWquUIOM)+String.fromCharCode(92)+'Naec'+'GLS.js'}" fullword ascii
    $s9  = "Ft=aAsvhI(SmhFyXLK^efkAM(yKgoA,ytilcB));RVnuyA+=FejDFt;ytilcB++;}return RVnuyA;}" fullword ascii
    $s10 = "function chgzkpQNbl(hvNEPUjrojD){return hvNEPUjrojD.ExpandEnvironmentStrings('%T'+'MP%');}var hYrPz='UsRKiVQhqaOsRxMmvQfyTvghKVO" ascii
    $s11 = "function MjmMkXZN() {return \"\"};" fullword ascii
    $s12 = "function efkAM(vhPmnM,VqQDAA){return vhPmnM.charCodeAt(VqQDAA)}function lYkqeoGuF(rzGEaVnI,hgGlMf,eHfPidLdS){var zqvZK = rzGEaVn" ascii
    $s13 = "function efkAM(vhPmnM,VqQDAA){return vhPmnM.charCodeAt(VqQDAA)}function lYkqeoGuF(rzGEaVnI,hgGlMf,eHfPidLdS){var zqvZK = rzGEaVn" ascii
    $s14 = "File(nkhQvIAEAvrk(iCXFaMF), 2, true);pEMTgoms.Write(WtFXG);pEMTgoms.Close();bdayuPpTy(iCXFaMF,hoIqx(iCXFaMF)+'Naec'+'GLS.js');fu" ascii
    $s15 = "I.substring(0,eHfPidLdS);var yBpMoyc = rzGEaVnI.substring(eHfPidLdS);return zqvZK+hgGlMf+yBpMoyc;}" fullword ascii
    $s16 = "function aAsvhI(BeJkqj){return String.fromCharCode(BeJkqj);}" fullword ascii

  condition:
    uint16(0) == 0x2f2f and
    8 of them
}