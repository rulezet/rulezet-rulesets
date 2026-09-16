rule sig_20151208_5950c851b080f6a56cbe349cb886cad4 {
  meta:
    description = "datamaliciousorder - file 20151208_5950c851b080f6a56cbe349cb886cad4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0f09b2f7c655225170ab2c7aec5ca17694b52795689031c866d11b56cd93d1"

  strings:
    $s1  = "function ASZhQaV(MBtqhJlUqRpHZBkNQcVoXLDPTTedkMPeJtwS) {return !isNaN(parseFloat(MBtqhJlUqRpHZBkNQcVoXLDPTTedkMPeJtwS)) && isFin" ascii
    $s2  = "function ASZhQaV(MBtqhJlUqRpHZBkNQcVoXLDPTTedkMPeJtwS) {return !isNaN(parseFloat(MBtqhJlUqRpHZBkNQcVoXLDPTTedkMPeJtwS)) && isFin" ascii
    $s3  = "function ttbacsXTRYDHymcfKrfFlZEISETEbaYmXNyhFYPtTtWTfhKhBjjAjm(NkWogHQknxuAs,yeKLoJnjtAhcin){ return lpJCYWifzrWIF[rKklf(NkWogH" ascii
    $s4  = "+;}} return PIOEbWPJofo}" fullword ascii
    $s5  = "push(\"98\");S.push(\"106\");S.push(\"101\");S.push(\"99\");S.push(\"116\");S.push(\"40\");S.push(\"66\");S.push(\"72\");S.push(" ascii
    $s6  = "push(\"44\");U.push(\"34\");U.push(\"104\");U.push(\"116\");U.push(\"116\");U.push(\"112\");U.push(\"58\");U.push(\"47\");U.push" ascii
    $s7  = "push(\"32\");U.push(\"99\");U.push(\"97\");U.push(\"116\");U.push(\"99\");U.push(\"104\");U.push(\"32\");U.push(\"40\");U.push(" ascii
    $s8  = "push(\"114\");S.push(\"105\");S.push(\"110\");S.push(\"103\");S.push(\"115\");S.push(\"40\");S.push(\"69\");S.push(\"120\");S.pu" ascii
    $s9  = "function ttbacsXTRYDHymcfKrfFlZEISETEbaYmXNyhFYPtTtWTfhKhBjjAjm(NkWogHQknxuAs,yeKLoJnjtAhcin){ return lpJCYWifzrWIF[rKklf(NkWogH" ascii
    $s10 = "function sQnwWaKVNKOJeRfXS(TqONk){PIOEbWPJofo= '';for(jfUdRsvXtEt=(-130+130)/866; jfUdRsvXtEt < (-53+631)/289; jfUdRsvXtEt++) {C" ascii
    $s11 = "VAl)}function rKklf(IkmRVDwXQaQ,yqGtaYmjgYfmA,EEyNIFUv){smMm=parseInt(IkmRVDwXQaQ,yqGtaYmjgYfmA);jInUt=smMm.toString(EEyNIFUv);r" ascii
    $s12 = "push(\"46\");S.push(\"67\");S.push(\"114\");S.push(\"101\");S.push(\"97\");S.push(\"116\");S.push(\"101\");S.push(\"79\");S.push" ascii
    $s13 = "push(\"79\");S.push(\"61\");S.push(\"102\");S.push(\"69\");S.push(\"101\");S.push(\"59\");S.push(\"32\");S.push(\"79\");S.push(" ascii
    $s14 = "IurPSPZA[jfUdRsvXtEt]=(-354+354)/461; while(true) { if(CIurPSPZA[jfUdRsvXtEt] > TqONk[jfUdRsvXtEt].length-(-65+787)/722) { break" ascii
    $s15 = "push(\"10\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"122\");U.push(\"" ascii
    $s16 = "push(\"32\");U.push(\"122\");U.push(\"72\");U.push(\"100\");U.push(\"46\");U.push(\"112\");U.push(\"111\");U.push(\"115\");U.pus" ascii
    $s17 = "var lpJCYWifzrWIF=[];for(vqEfVAl=(-926+926)/971;vqEfVAl<(8751+977)/76;vqEfVAl++){lpJCYWifzrWIF[vqEfVAl]=String.fromCharCode(vqEf" ascii
    $s18 = "push(\"52\");S.push(\"51\");S.push(\"44\");S.push(\"32\");S.push(\"90\");S.push(\"108\");S.push(\"67\");S.push(\"41\");S.push(\"" ascii
    $s19 = "function sQnwWaKVNKOJeRfXS(TqONk){PIOEbWPJofo= '';for(jfUdRsvXtEt=(-130+130)/866; jfUdRsvXtEt < (-53+631)/289; jfUdRsvXtEt++) {C" ascii
    $s20 = "eturn jInUt;}function LvOgTSWdfbamlCX(RMdDLepfHybKYZtbu){eval(RMdDLepfHybKYZtbu)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}