rule sig_20151217_228814d7390d296b83b9160a0faa31c2 {
  meta:
    description = "datamaliciousorder - file 20151217_228814d7390d296b83b9160a0faa31c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c04e13b3e55ce2b981133fea86ad6699e9f403369eaf64aa3fd25d6cc4f89287"

  strings:
    $s1  = "function WpbkqSAMOotnlyWkH(IAPeP){mfinKKlqyVn= '';CcXLhILxutV=Math.round((Math.pow(Math.sin(386), 2) + Math.pow(Math.cos(386), 2" ascii
    $s2  = "(Math.cos(434), 2) - 1)));} vUJawbrIf[CcXLhILxutV]++;}CcXLhILxutV++;} return mfinKKlqyVn}" fullword ascii
    $s3  = "h.pow(Math.cos(515), 2) - 1)); while(true) { if(vUJawbrIf[CcXLhILxutV] > IAPeP[CcXLhILxutV].length-(-267+850)/583) { break; } if" ascii
    $s4  = ") - 1));while(true){if (CcXLhILxutV >= (-437+959)/87){break;}vUJawbrIf[CcXLhILxutV]=Math.round((Math.pow(Math.sin(515), 2) + Mat" ascii
    $s5  = "function WpbkqSAMOotnlyWkH(IAPeP){mfinKKlqyVn= '';CcXLhILxutV=Math.round((Math.pow(Math.sin(386), 2) + Math.pow(Math.cos(386), 2" ascii
    $s6  = "function npOJhKc(KQJpfWdjBIjPfMPTPtRpNlMgmlUHznAnlwmK) {return !CSGBBpZKgoJ(bMqNhGwJGniUYeG(KQJpfWdjBIjPfMPTPtRpNlMgmlUHznAnlwmK" ascii
    $s7  = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s8  = "function i(SKeeDRjPtoNeRV,pBXFucNYnVQFs,MnUtFwQdlkG) {SKeeDRjPtoNeRV[pBXFucNYnVQFs]=MnUtFwQdlkG;}" fullword ascii
    $s9  = "function JoKdfgCrcluU(oaYmTlVeCJBiw) {return isFinite(oaYmTlVeCJBiw);}" fullword ascii
    $s10 = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s11 = "function CSGBBpZKgoJ(xVFgyqtXqTjsUd) {return isNaN(xVFgyqtXqTjsUd);}" fullword ascii
    $s12 = "function bMqNhGwJGniUYeG(RvQYoMczRmQNGwnpwdr) {return parseFloat(RvQYoMczRmQNGwnpwdr);}" fullword ascii
    $s13 = "F);return NOLBZ;}" fullword ascii
    $s14 = "function JhuoxwJmSKKHikkYQRAZrjgiZqEcCzbmpbcYtenyPyklTvFUzZaeWe(sVwyyTfwUtpEe,ZCWNUMECGwNAIq){ return KPHsvnP[mscyqckd[kwJsR(sVw" ascii
    $s15 = "function npOJhKc(KQJpfWdjBIjPfMPTPtRpNlMgmlUHznAnlwmK) {return !CSGBBpZKgoJ(bMqNhGwJGniUYeG(KQJpfWdjBIjPfMPTPtRpNlMgmlUHznAnlwmK" ascii
    $s16 = "function wovvAHZZRpzTJRnch(APULYNHdKu,vCiKFQvUqP) {return parseInt(APULYNHdKu,vCiKFQvUqP);}" fullword ascii
    $s17 = "function kwJsR(TbNfFAqmTLf,uLlIduoHMjKSL,VfORNkWF){LVmw=wovvAHZZRpzTJRnch(TbNfFAqmTLf,uLlIduoHMjKSL);NOLBZ=LVmw.toString(VfORNkW" ascii
    $s18 = "function JhuoxwJmSKKHikkYQRAZrjgiZqEcCzbmpbcYtenyPyklTvFUzZaeWe(sVwyyTfwUtpEe,ZCWNUMECGwNAIq){ return KPHsvnP[mscyqckd[kwJsR(sVw" ascii
    $s19 = "function kwJsR(TbNfFAqmTLf,uLlIduoHMjKSL,VfORNkWF){LVmw=wovvAHZZRpzTJRnch(TbNfFAqmTLf,uLlIduoHMjKSL);NOLBZ=LVmw.toString(VfORNkW" ascii
    $s20 = "function x(nmbHbTXskGUb,MBpivMhxKiikjA){nmbHbTXskGUb.push(MBpivMhxKiikjA);}" fullword ascii

  condition:
    uint16(0) == 0x736d and
    8 of them
}