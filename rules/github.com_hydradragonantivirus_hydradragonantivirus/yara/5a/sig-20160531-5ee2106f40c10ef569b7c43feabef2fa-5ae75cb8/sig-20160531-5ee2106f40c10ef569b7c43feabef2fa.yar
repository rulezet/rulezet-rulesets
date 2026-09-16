rule sig_20160531_5ee2106f40c10ef569b7c43feabef2fa {
  meta:
    description = "datamaliciousorder - file 20160531_5ee2106f40c10ef569b7c43feabef2fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "670aeea4593db8ae89b4147154dbf3edb9322ef017a94628c21eb75921d9d4a0"

  strings:
    $s1  = "var KnLMDf=function(){return WScript.CreateObject(aLujyCYbDjyVWfREectcsKY[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function SsZwELPCqLzeZLb(lmWFiBcsULuJWHGYrYAIrJub,bSsIzosHGPVjhiEyRGbNxpaR){return lmWFiBcsULuJWHGYrYAIrJub.charAt(bSsIzosHGPVjh" ascii
    $s3  = "function SsZwELPCqLzeZLb(lmWFiBcsULuJWHGYrYAIrJub,bSsIzosHGPVjhiEyRGbNxpaR){return lmWFiBcsULuJWHGYrYAIrJub.charAt(bSsIzosHGPVjh" ascii
    $s4  = "function aHrKocgmKApuotPLigYFYi(FyeZdcrrExkfUvu,ARXNrAmZppuIztOBrQQvGDo,aSFhETkuHhEyQxeYeRtvePS){return String.fromCharCode(FyeZ" ascii
    $s5  = "function aHrKocgmKApuotPLigYFYi(FyeZdcrrExkfUvu,ARXNrAmZppuIztOBrQQvGDo,aSFhETkuHhEyQxeYeRtvePS){return String.fromCharCode(FyeZ" ascii
    $s6  = ";}return wTzSmiLUsgS.substring(3,wTzSmiLUsgS.length);}" fullword ascii
    $s7  = "function UGRDNtFIvC(qrbBtGeqBTjiq) {var NWvcNtUJmOscbDbDaGdXoNO = ZzslmKaHuiGm.join(aLujyCYbDjyVWfREectcsKY[7]);var sVhqineIlATX" ascii
    $s8  = "= aHrKocgmKApuotPLigYFYi(sVhqineIlATXIde, ahLpXvaBgJwAAHv, ISXOybflhWELOpoKcMNaElD);} while (VqvYCPPYkFMMpT < qrbBtGeqBTjiq.leng" ascii
    $s9  = "function irAefxnZnpdCVx(UlMbbpZBQgopjKQ,IpPJXJtsZrzarKlIsT){return String.fromCharCode(UlMbbpZBQgopjKQ,IpPJXJtsZrzarKlIsT);}" fullword ascii
    $s10 = "function uCClStHqq(){return KnLMDf.ExpandEnvironmentStrings(FhTltZLP())}" fullword ascii
    $s11 = "th);return DcmAvjiJImI;}" fullword ascii
    $s12 = "function FhTltZLP(){return uhvKmHYtEqn(aLujyCYbDjyVWfREectcsKY[9],[1,5,7],aLujyCYbDjyVWfREectcsKY[10]);}" fullword ascii
    $s13 = "(rbJbSNghFv,0x1,0x0)}function YCzAgMoAnAvSL(XZJkvCFrD,IsVRj,nmggfqgFvX){var yCotkQkAfOW=XZJkvCFrD.createtextfile(IsVRj,true);yCo" ascii
    $s14 = "push(\"U\");ZzslmKaHuiGm.push(\"V\");ZzslmKaHuiGm.push(\"W\");ZzslmKaHuiGm.push(\"X\");ZzslmKaHuiGm.push(\"Y\");ZzslmKaHuiGm.pus" ascii
    $s15 = "fb(sVhqineIlATXIde);else if (dIPHwCYxm == 64) DcmAvjiJImI += irAefxnZnpdCVx(sVhqineIlATXIde, ahLpXvaBgJwAAHv);else DcmAvjiJImI +" ascii
    $s16 = "function cNRFTtCqNVlj(){return uhvKmHYtEqn(aLujyCYbDjyVWfREectcsKY[11],[2,4,8,10],aLujyCYbDjyVWfREectcsKY[12]);}" fullword ascii
    $s17 = "function FGAUMnVvdbgZIp(){return uhvKmHYtEqn(aLujyCYbDjyVWfREectcsKY[13],[0,3,6],aLujyCYbDjyVWfREectcsKY[14]);}" fullword ascii
    $s18 = "function uhvKmHYtEqn(gGPJRHVpBLZ,CVYTQKuvGmSvmH,yoobuJWpfpWhS){dbJkOKkwQjJB=gGPJRHVpBLZ.split(yoobuJWpfpWhS);wTzSmiLUsgS = aLujy" ascii
    $s19 = "function uhvKmHYtEqn(gGPJRHVpBLZ,CVYTQKuvGmSvmH,yoobuJWpfpWhS){dbJkOKkwQjJB=gGPJRHVpBLZ.split(yoobuJWpfpWhS);wTzSmiLUsgS = aLujy" ascii
    $s20 = "function zSsbjvzFscVQUDNbIYHnr(PeHkveVYGxJBjWgHHLj,zEJZWhKGOpyGdDoWMlJTpEe){return PeHkveVYGxJBjWgHHLj.indexOf(zEJZWhKGOpyGdDoWM" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}