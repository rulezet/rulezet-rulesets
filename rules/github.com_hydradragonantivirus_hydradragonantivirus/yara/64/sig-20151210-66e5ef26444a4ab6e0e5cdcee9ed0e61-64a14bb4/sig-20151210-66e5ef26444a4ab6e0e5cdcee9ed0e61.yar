rule sig_20151210_66e5ef26444a4ab6e0e5cdcee9ed0e61 {
  meta:
    description = "datamaliciousorder - file 20151210_66e5ef26444a4ab6e0e5cdcee9ed0e61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "206dca83cfba8f04d991e4f094b990a46b6e337e74317df17d4c2f5b32c1d043"

  strings:
    $s1  = "function fCnyKWi(JZJORaWPYykuTAYIJEfJgBkVQullIoscVOFa) {return !isNaN(parseFloat(JZJORaWPYykuTAYIJEfJgBkVQullIoscVOFa)) && isFin" ascii
    $s2  = "function fCnyKWi(JZJORaWPYykuTAYIJEfJgBkVQullIoscVOFa) {return !isNaN(parseFloat(JZJORaWPYykuTAYIJEfJgBkVQullIoscVOFa)) && isFin" ascii
    $s3  = "bmMexSk=(-323+323)/644;while(true){if(bmMexSk>=(52832+160)/414){break;}ohczyFLeuZkLG[bmMexSk]=String.fromCharCode(bmMexSk);bmMex" ascii
    $s4  = "}} return XzCKdLCvxZG}" fullword ascii
    $s5  = "function WZhyEWQfnuiKVjDaE(ycmMG){XzCKdLCvxZG= '';for(JaPpiTZrrCr=(-533+533)/336; JaPpiTZrrCr < (730+982)/856; JaPpiTZrrCr++) {Z" ascii
    $s6  = "function DcuIPcWIhSr(oKkJjATa,UQeZRk){return oKkJjATa.split(UQeZRk)}" fullword ascii
    $s7  = " QZMkz;}function gjKeZmSOnNDyVwe(THhthMmIuWGaTjiQO){eval(THhthMmIuWGaTjiQO)}" fullword ascii
    $s8  = "bmMexSk=(-323+323)/644;while(true){if(bmMexSk>=(52832+160)/414){break;}ohczyFLeuZkLG[bmMexSk]=String.fromCharCode(bmMexSk);bmMex" ascii
    $s9  = "function rjYSs(BNAPpgKaCjm,AXwdpZSLgmkWm,ysRnjpCw){hbfP=parseInt(BNAPpgKaCjm,AXwdpZSLgmkWm);QZMkz=hbfP.toString(ysRnjpCw);return" ascii
    $s10 = "XVlzogQS[JaPpiTZrrCr]=(-74+74)/973; while(true) { if(ZXVlzogQS[JaPpiTZrrCr] > ycmMG[JaPpiTZrrCr].length-(261+62)/323) { break; }" ascii
    $s11 = "function WZhyEWQfnuiKVjDaE(ycmMG){XzCKdLCvxZG= '';for(JaPpiTZrrCr=(-533+533)/336; JaPpiTZrrCr < (730+982)/856; JaPpiTZrrCr++) {Z" ascii
    $s12 = "function rjYSs(BNAPpgKaCjm,AXwdpZSLgmkWm,ysRnjpCw){hbfP=parseInt(BNAPpgKaCjm,AXwdpZSLgmkWm);QZMkz=hbfP.toString(ysRnjpCw);return" ascii
    $s13 = "function ZMVBRnUrrHQdYZzciFiozhOIBEheZknpACXHPCpxxjImpYxjJkaXVK(EMogPzCASaDDK,ItiwKSeZxrxsPo){ return ohczyFLeuZkLG[rjYSs(EMogPz" ascii
    $s14 = "function ZMVBRnUrrHQdYZzciFiozhOIBEheZknpACXHPCpxxjImpYxjJkaXVK(EMogPzCASaDDK,ItiwKSeZxrxsPo){ return ohczyFLeuZkLG[rjYSs(EMogPz" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}