rule sig_20151215_3a0a5776be5150f5345e8b2af6180095 {
  meta:
    description = "datamaliciousorder - file 20151215_3a0a5776be5150f5345e8b2af6180095.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09982085c678ad69e850348a2090a05c55b5360c920302d652dc51cff49f8ab3"

  strings:
    $s1  = "Math.pow(Math.cos(359), 2) - 1)); while(true) { if(lwwtnIrnK[hPKGQzIDjEz] > IQets[hPKGQzIDjEz].length-(-627+934)/307) { break; }" ascii
    $s2  = "th.pow(Math.cos(780), 2) - 1)));} lwwtnIrnK[hPKGQzIDjEz]++;}} return hqgkWWphERq}" fullword ascii
    $s3  = "function DeLaNfAOKwpKGGUUI(IQets){hqgkWWphERq= B[1775];for(hPKGQzIDjEz=Math.round((Math.pow(Math.sin(702), 2) + Math.pow(Math.co" ascii
    $s4  = "UMud)) {return (String.fromCharCode(FaNptMpAmFCOUMud) + String.fromCharCode((57766+714)/731));}}" fullword ascii
    $s5  = "function a(NlisjZywKvap,yFgFcxYatkdcpk){NlisjZywKvap.push(yFgFcxYatkdcpk);}function E8(FaNptMpAmFCOUMud){if(QLSeZkn(FaNptMpAmFCO" ascii
    $s6  = "function DeLaNfAOKwpKGGUUI(IQets){hqgkWWphERq= B[1775];for(hPKGQzIDjEz=Math.round((Math.pow(Math.sin(702), 2) + Math.pow(Math.co" ascii
    $s7  = "function QLSeZkn(IALSGmAGvrrBbsfLHXHULIcYEdBcchMzAteW) {return !isNaN(parseFloat(IALSGmAGvrrBbsfLHXHULIcYEdBcchMzAteW)) && isFin" ascii
    $s8  = "function a(NlisjZywKvap,yFgFcxYatkdcpk){NlisjZywKvap.push(yFgFcxYatkdcpk);}function E8(FaNptMpAmFCOUMud){if(QLSeZkn(FaNptMpAmFCO" ascii
    $s9  = "function QLSeZkn(IALSGmAGvrrBbsfLHXHULIcYEdBcchMzAteW) {return !isNaN(parseFloat(IALSGmAGvrrBbsfLHXHULIcYEdBcchMzAteW)) && isFin" ascii
    $s10 = "function MKmBmRuUeHR(SmUbixLE,mphwjS){return SmUbixLE.split(mphwjS)}" fullword ascii
    $s11 = "function zTNjrTHXyGfOJouRDbeeCCZrKbcFyvyUpGrPnMTzrcIiFpDlDRRgzx(jaCuMJGILSsbH,WGVJVkzzjAqlah){ return YuRnPHe[fmNcVAAG[zBlpE(jaC" ascii
    $s12 = "var B=new Array();" fullword ascii
    $s13 = "function zBlpE(ytXrTzwlCvG,dqpbOIIMBwGtT,BtIcGLOv){aEyr=parseInt(ytXrTzwlCvG,dqpbOIIMBwGtT);VPliI=aEyr.toString(BtIcGLOv);return" ascii
    $s14 = "function zTNjrTHXyGfOJouRDbeeCCZrKbcFyvyUpGrPnMTzrcIiFpDlDRRgzx(jaCuMJGILSsbH,WGVJVkzzjAqlah){ return YuRnPHe[fmNcVAAG[zBlpE(jaC" ascii
    $s15 = "function zBlpE(ytXrTzwlCvG,dqpbOIIMBwGtT,BtIcGLOv){aEyr=parseInt(ytXrTzwlCvG,dqpbOIIMBwGtT);VPliI=aEyr.toString(BtIcGLOv);return" ascii
    $s16 = " VPliI;}function mEZhaLaXCzNZlbM(txxVJcqRAUULFCCAW,BPfotLdKaFJhZPpcnQbTpPpUtNQcYkxOrm,vtGNURIrVbehMRziDxkxMxGASxpSptwGbbf){eval(" ascii
    $s17 = "function mEZhaLaXCzNZlbM(txxVJcqRAUULFCCAW){eval(txxVJcqRAUULFCCAW)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}