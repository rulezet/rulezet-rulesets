rule sig_20160527_5da79070bab8015e51bc0f5479d3e496 {
  meta:
    description = "datamaliciousorder - file 20160527_5da79070bab8015e51bc0f5479d3e496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeae1fec3f00bb16300e9f860f4eb6e6f8e87ed8ab032cd270acec7a42b70c0f"

  strings:
    $s1  = "function TliVgRa(mwzVYnqaBEmGWtZMJjV,eSzIttGeX){return mwzVYnqaBEmGWtZMJjV.charAt(eSzIttGeX);}" fullword ascii
    $s2  = "function yfzhgfaPCAjJRD() {return WScript;}function PhSTyxlGUalxlA(){return epHzPKZ.ExpandEnvironmentStrings(mbLYeoeTB())}" fullword ascii
    $s3  = "var wMmUT = FRLYldNlyhr.createtextfile(epHzPKZ.ExpandEnvironmentStrings(xLAWDAfF[2]+xLAWDAfF[3])+String.fromCharCode(92)+xLAWDAf" ascii
    $s4  = "function RGMoERoxmzV(UoVCEGXGrYAWC) {var hjSsT = gHsIPKDhqvSUKdMy.join(xLAWDAfF[6]);var mqlWqTZ, IhicIYjsusJOKHA, MdbSQLXkNCkb, " ascii
    $s5  = "function ceuaPfUK(jEcnTwnhBNrm,mGfEFP) {var pLYsTzpLFdmT=[xLAWDAfF[15]];jEcnTwnhBNrm[pLYsTzpLFdmT[0]](mGfEFP,0x1,0x0)}" fullword ascii
    $s6  = "function PkdaAl(XNipz,UBAsGtLpFkmthEf){return XNipz.indexOf(UBAsGtLpFkmthEf);}" fullword ascii
    $s7  = "function wlJeYWAdbj(CGzlVZhMkABtNVMqIMTDb,MlMQGrFsRnb,ulCFDtFwqDl){return String.fromCharCode(CGzlVZhMkABtNVMqIMTDb,MlMQGrFsRnb," ascii
    $s8  = "function YLkFXU(WwSsXOuawv,jvyRYU,ijlYqsmuRUUs){ikpyiIHo=WwSsXOuawv.split(ijlYqsmuRUUs);geJGblGxWVEYd = xLAWDAfF[14];for(RBpZPHm" ascii
    $s9  = "function l(NKwFWkwIF){return String.fromCharCode(NKwFWkwIF);}" fullword ascii
    $s10 = "YjsusJOKHA, MdbSQLXkNCkb);} while (ZEAvrMjGhwrVEyVcxIoi < UoVCEGXGrYAWC.length);return ZwNmkGRHcvrrIax;}" fullword ascii
    $s11 = "function quRXx(){return YLkFXU(xLAWDAfF[12],[0,3,6],xLAWDAfF[13]);}" fullword ascii
    $s12 = "else if (ZKOjp == 64) ZwNmkGRHcvrrIax += wyQVHdxInHU(mqlWqTZ, IhicIYjsusJOKHA);else ZwNmkGRHcvrrIax += wlJeYWAdbj(mqlWqTZ, IhicI" ascii
    $s13 = "function wyQVHdxInHU(KLnFoisY,WGMmgwOvpEFGKPzqLIU){return String.fromCharCode(KLnFoisY,WGMmgwOvpEFGKPzqLIU);}" fullword ascii
    $s14 = "function mbLYeoeTB(){return YLkFXU(xLAWDAfF[8],[1,5,7],xLAWDAfF[9]);}" fullword ascii
    $s15 = "function fhoxYlXHV(){return YLkFXU(xLAWDAfF[10],[2,4,8,10],xLAWDAfF[11]);}" fullword ascii
    $s16 = "function YLkFXU(WwSsXOuawv,jvyRYU,ijlYqsmuRUUs){ikpyiIHo=WwSsXOuawv.split(ijlYqsmuRUUs);geJGblGxWVEYd = xLAWDAfF[14];for(RBpZPHm" ascii
    $s17 = "function wlJeYWAdbj(CGzlVZhMkABtNVMqIMTDb,MlMQGrFsRnb,ulCFDtFwqDl){return String.fromCharCode(CGzlVZhMkABtNVMqIMTDb,MlMQGrFsRnb," ascii
    $s18 = "var FRLYldNlyhr=function(){return new ActiveXObject(xLAWDAfF[0]);}();" fullword ascii
    $s19 = "cQfIVAh=0;RBpZPHmcQfIVAh<jvyRYU.length;RBpZPHmcQfIVAh++) {geJGblGxWVEYd+=ikpyiIHo[jvyRYU[RBpZPHmcQfIVAh]];}return geJGblGxWVEYd." ascii
    $s20 = "function RGMoERoxmzV(UoVCEGXGrYAWC) {var hjSsT = gHsIPKDhqvSUKdMy.join(xLAWDAfF[6]);var mqlWqTZ, IhicIYjsusJOKHA, MdbSQLXkNCkb, " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}