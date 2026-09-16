rule sig_20160527_e0aeb87029560803321460df112506ad {
  meta:
    description = "datamaliciousorder - file 20160527_e0aeb87029560803321460df112506ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e2a2c7a7e67c32129b2ef40234cb3d02414503fe93dd43a972b88d6f546bd14"

  strings:
    $s1  = "function CHWQzDSN(wXyyXjLFtpXDi) {var ZxYnImsyzucGJAh = rmBhYTnJrQMjAZhsqgWtgZ.join(haSfTaj[6]);var Lrknz, tMbKjsziSGbLBnzqldVc," ascii
    $s2  = "function BoUtRXia() {return WScript;}function yOnhlgPo(){return cnbNQqssXns.ExpandEnvironmentStrings(mKSksBKH())}" fullword ascii
    $s3  = "function CHWQzDSN(wXyyXjLFtpXDi) {var ZxYnImsyzucGJAh = rmBhYTnJrQMjAZhsqgWtgZ.join(haSfTaj[6]);var Lrknz, tMbKjsziSGbLBnzqldVc," ascii
    $s4  = "nz, tMbKjsziSGbLBnzqldVc, mkYOUPFGlM);} while (NLJFrdQAAvJBPhMUr < wXyyXjLFtpXDi.length);return gVFDI;}" fullword ascii
    $s5  = "function JDzwpeRAUsOtgkEyqV(VpkNqKJLatEtEsriZBz,vhoJmbdSbFoHK,wahYvApuzFVKxlHVolyuEN){return String.fromCharCode(VpkNqKJLatEtEsr" ascii
    $s6  = "HtlxDttas.length;Iyuurw++) {HLVePCxhtJHJS+=pMkJKBkgvf[HtlxDttas[Iyuurw]];}return HLVePCxhtJHJS.substring(3,HLVePCxhtJHJS.length)" ascii
    $s7  = "function JDzwpeRAUsOtgkEyqV(VpkNqKJLatEtEsriZBz,vhoJmbdSbFoHK,wahYvApuzFVKxlHVolyuEN){return String.fromCharCode(VpkNqKJLatEtEsr" ascii
    $s8  = "nz);else if (ysdxPeYmxyUl == 64) gVFDI += CdrAceOsNtEaqpJQcVUd(Lrknz, tMbKjsziSGbLBnzqldVc);else gVFDI += JDzwpeRAUsOtgkEyqV(Lrk" ascii
    $s9  = "function KwKFKvCtoryWY(RAKsA,XQCAPklrOeDQapMLkrXOlXIZ){return RAKsA.charAt(XQCAPklrOeDQapMLkrXOlXIZ);}" fullword ascii
    $s10 = "var JlJPLhPQ=function(){return new ActiveXObject(haSfTaj[0]);}();" fullword ascii
    $s11 = "var zHjfAeHmrzLCS = JlJPLhPQ.createtextfile(cnbNQqssXns.ExpandEnvironmentStrings(haSfTaj[2]+haSfTaj[3])+String.fromCharCode(92)+" ascii
    $s12 = "var cnbNQqssXns=function(){return BoUtRXia().CreateObject(haSfTaj[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "haSfTaj[4],true);" fullword ascii
    $s14 = "function JK(siorF){return String.fromCharCode(siorF);}" fullword ascii
    $s15 = "function YfNxAbbbkWu(QOhllYgKnYJorY,wBeJvjcXYRnBrWRMrEBE){return QOhllYgKnYJorY.indexOf(wBeJvjcXYRnBrWRMrEBE);}" fullword ascii
    $s16 = "function UiAHlXdW(pvGroAMbZrH,owSRq) {var ySnWu=[haSfTaj[15]];pvGroAMbZrH[ySnWu[0]](owSRq,0x1,0x0)}" fullword ascii
    $s17 = "function CdrAceOsNtEaqpJQcVUd(kTdufGBECwleYbedURK,TjghaAfqx){return String.fromCharCode(kTdufGBECwleYbedURK,TjghaAfqx);}" fullword ascii
    $s18 = "function IjnSFDLOWff(){return NMSkgcALlLczN(haSfTaj[12],[0,3,6],haSfTaj[13]);}" fullword ascii
    $s19 = "function gUwnmXb(){return NMSkgcALlLczN(haSfTaj[10],[2,4,8,10],haSfTaj[11]);}" fullword ascii
    $s20 = "function NMSkgcALlLczN(lzCJq,HtlxDttas,BalYUNc){pMkJKBkgvf=lzCJq.split(BalYUNc);HLVePCxhtJHJS = haSfTaj[14];for(Iyuurw=0;Iyuurw<" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}