rule sig_20151215_d11aa6249ab62ffbc3e040a2c2db5da6 {
  meta:
    description = "datamaliciousorder - file 20151215_d11aa6249ab62ffbc3e040a2c2db5da6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e59f0ca3d6e402fb640f5d6df51ed5bf9f36915713417b9bb97990aa9c35366c"

  strings:
    $s1  = "Math.cos(351), 2) - 1)));} QIFTanGxP[vXqrgjGvJTY]++;}} return ygyYpEgJovX}" fullword ascii
    $s2  = "ath.pow(Math.cos(75), 2) - 1)); while(true) { if(QIFTanGxP[vXqrgjGvJTY] > ibsuO[vXqrgjGvJTY].length-(192+628)/820) { break; } if" ascii
    $s3  = "function fxfKIzJGbBGcjqgfR(ibsuO){ygyYpEgJovX= g[1759];for(vXqrgjGvJTY=Math.round((Math.pow(Math.sin(682), 2) + Math.pow(Math.co" ascii
    $s4  = "function fxfKIzJGbBGcjqgfR(ibsuO){ygyYpEgJovX= g[1759];for(vXqrgjGvJTY=Math.round((Math.pow(Math.sin(682), 2) + Math.pow(Math.co" ascii
    $s5  = "function f(SKioGIkknYAV,XgfMCEFBLOnoWd){SKioGIkknYAV.push(XgfMCEFBLOnoWd);}function T7(LoRmhCgyWbcnaobD){if(QZnIEvh(LoRmhCgyWbcn" ascii
    $s6  = "aobD)) {return (String.fromCharCode(LoRmhCgyWbcnaobD) + String.fromCharCode((22108+467)/301));}}" fullword ascii
    $s7  = "function QZnIEvh(FWQPOhTFtYEbsMVNjvDYDpauRIpKFHZAhBEx) {return !isNaN(parseFloat(FWQPOhTFtYEbsMVNjvDYDpauRIpKFHZAhBEx)) && isFin" ascii
    $s8  = "function QZnIEvh(FWQPOhTFtYEbsMVNjvDYDpauRIpKFHZAhBEx) {return !isNaN(parseFloat(FWQPOhTFtYEbsMVNjvDYDpauRIpKFHZAhBEx)) && isFin" ascii
    $s9  = " FIlDm;}function YDEKeNVSZLvbMIn(OuEmLhIYVOtRXwzPK,NsTbOdyoIjQAnWwdyQMYaApRcYzQpNdbwe,NyJKREKzSVWwLbOMXRZbQHUdaybJyYHtqZA){eval(" ascii
    $s10 = "function uZDBk(zLDsPrTHZKh,RNIBFBaRoSNor,USysCUpa){WFoH=parseInt(zLDsPrTHZKh,RNIBFBaRoSNor);FIlDm=WFoH.toString(USysCUpa);return" ascii
    $s11 = "function YDEKeNVSZLvbMIn(OuEmLhIYVOtRXwzPK){eval(OuEmLhIYVOtRXwzPK)}" fullword ascii
    $s12 = "function f(SKioGIkknYAV,XgfMCEFBLOnoWd){SKioGIkknYAV.push(XgfMCEFBLOnoWd);}function T7(LoRmhCgyWbcnaobD){if(QZnIEvh(LoRmhCgyWbcn" ascii
    $s13 = "function uZDBk(zLDsPrTHZKh,RNIBFBaRoSNor,USysCUpa){WFoH=parseInt(zLDsPrTHZKh,RNIBFBaRoSNor);FIlDm=WFoH.toString(USysCUpa);return" ascii
    $s14 = "function AmehdDxreap(dfLxiwOr,ydfeEQ){return dfLxiwOr.split(ydfeEQ)}" fullword ascii
    $s15 = "function eZmCZLTFkghXwOviJOcAzZPsmbULzrPSrekeWpwlQVkXhkhZlbbxeH(HOLgeuLXSrwVA,JGWqnxXQOKlUcq){ return KmEkvZN[zXluXnob[uZDBk(HOL" ascii
    $s16 = "function eZmCZLTFkghXwOviJOcAzZPsmbULzrPSrekeWpwlQVkXhkhZlbbxeH(HOLgeuLXSrwVA,JGWqnxXQOKlUcq){ return KmEkvZN[zXluXnob[uZDBk(HOL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}