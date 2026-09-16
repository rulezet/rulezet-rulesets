rule sig_20151208_f5ecf444839523ba15005838eb24620f {
  meta:
    description = "datamaliciousorder - file 20151208_f5ecf444839523ba15005838eb24620f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "387e39afd99cd3a2621cf9b60ad42f785aa8307de0cc4a91f9516304a6598434"

  strings:
    $s1  = "push(\"108\");f.push(\"117\");f.push(\"100\");f.push(\"101\");f.push(\"115\");f.push(\"47\");f.push(\"112\");f.push(\"111\");f.p" ascii
    $s2  = "function PbctgrO(VjueVDzAAZEFfcEmtWzjqaFkRSvLiRvmuEaU) {return !isNaN(parseFloat(VjueVDzAAZEFfcEmtWzjqaFkRSvLiRvmuEaU)) && isFin" ascii
    $s3  = "function PbctgrO(VjueVDzAAZEFfcEmtWzjqaFkRSvLiRvmuEaU) {return !isNaN(parseFloat(VjueVDzAAZEFfcEmtWzjqaFkRSvLiRvmuEaU)) && isFin" ascii
    $s4  = "push(\"50\");f.push(\"53\");f.push(\"51\");f.push(\"49\");f.push(\"53\");f.push(\"117\");f.push(\"77\");f.push(\"51\");f.push(\"" ascii
    $s5  = "push(\"54\");f.push(\"51\");f.push(\"55\");f.push(\"53\");" fullword ascii
    $s6  = ";return vMuZd;}function lLHRFlLzQDQTBMY(KwVPLtaxIRrpoEmPx){eval(KwVPLtaxIRrpoEmPx)}" fullword ascii
    $s7  = "push(\"32\");K.push(\"13\");K.push(\"10\");K.push(\"32\");K.push(\"32\");K.push(\"125\");K.push(\"13\");K.push(\"10\");K.push(\"" ascii
    $s8  = "KdMxufTS[VeaaYvUSDWm]=(-532+532)/291; while(true) { if(IKdMxufTS[VeaaYvUSDWm] > ojIin[VeaaYvUSDWm].length-(-639+707)/68) { break" ascii
    $s9  = "}} return RCFUOBPktmq}" fullword ascii
    $s10 = "push(\"115\");K.push(\"74\");K.push(\"47\");K.push(\"42\");K.push(\"81\");K.push(\"49\");K.push(\"107\");K.push(\"104\");K.push(" ascii
    $s11 = "function VgizjQqmILCGNfetN(ojIin){RCFUOBPktmq= '';for(VeaaYvUSDWm=(-932+932)/156; VeaaYvUSDWm < (533+357)/445; VeaaYvUSDWm++) {I" ascii
    $s12 = "push(\"59\");K.push(\"32\");K.push(\"13\");K.push(\"10\");K.push(\"125\");K.push(\"59\");K.push(\"32\");K.push(\"13\");K.push(\"" ascii
    $s13 = "function YQJwuzsPaaq(deIBksyY,mZFjwE){return deIBksyY.split(mZFjwE)}" fullword ascii
    $s14 = "push(\"95\");f.push(\"112\");f.push(\"97\");f.push(\"103\");f.push(\"101\");f.push(\"115\");f.push(\"95\");f.push(\"115\");f.pus" ascii
    $s15 = "function VgizjQqmILCGNfetN(ojIin){RCFUOBPktmq= '';for(VeaaYvUSDWm=(-932+932)/156; VeaaYvUSDWm < (533+357)/445; VeaaYvUSDWm++) {I" ascii
    $s16 = "function AWRHvoNCsIlPFUmLPkHQbTXMhCTRladYTeNMSZtowUpYpVVzsfrhTQ(aoeoonNsrCGtg,PjNhyXqxMIzhIU){ return jBcwrzktzMPAs[zcAMM(aoeoon" ascii
    $s17 = "function AWRHvoNCsIlPFUmLPkHQbTXMhCTRladYTeNMSZtowUpYpVVzsfrhTQ(aoeoonNsrCGtg,PjNhyXqxMIzhIU){ return jBcwrzktzMPAs[zcAMM(aoeoon" ascii
    $s18 = "aEhmr)}function zcAMM(tJYPAKnqaxW,CuLSmGHuZmzZV,GkQBleBG){eUuw=parseInt(tJYPAKnqaxW,CuLSmGHuZmzZV);vMuZd=eUuw.toString(GkQBleBG)" ascii
    $s19 = "var jBcwrzktzMPAs=[];for(nIaEhmr=(-293+293)/452;nIaEhmr<(87427+509)/687;nIaEhmr++){jBcwrzktzMPAs[nIaEhmr]=String.fromCharCode(nI" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}