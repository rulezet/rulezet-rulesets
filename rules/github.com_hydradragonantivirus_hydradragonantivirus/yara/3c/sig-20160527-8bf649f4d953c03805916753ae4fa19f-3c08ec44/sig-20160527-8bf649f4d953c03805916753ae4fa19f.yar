rule sig_20160527_8bf649f4d953c03805916753ae4fa19f {
  meta:
    description = "datamaliciousorder - file 20160527_8bf649f4d953c03805916753ae4fa19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a16fdf599e5be2ac3eee3686f74927b8e417597c889df3775a75164dd19ec44d"

  strings:
    $s1  = "function TuKDuiYs() {return WScript;}function IxsJKcvRmz(){return oZJwBF.ExpandEnvironmentStrings(CklpwquirXC())}" fullword ascii
    $s2  = "function reJCwhtDspsVnj(gMyZxgaCQiT,VvXbeVLvfzcf){return gMyZxgaCQiT.charAt(VvXbeVLvfzcf);}" fullword ascii
    $s3  = "push(\"t\");bkcOfiONtfhjNj.push(\"u\");bkcOfiONtfhjNj.push(\"v\");bkcOfiONtfhjNj.push(\"w\");bkcOfiONtfhjNj.push(\"x\");bkcOfiON" ascii
    $s4  = "function ajYsqnKGfFJVLCWALx(fAmKCccbnyu,lCmOprpXPoZWzhgWJ){return fAmKCccbnyu.indexOf(lCmOprpXPoZWzhgWJ);}" fullword ascii
    $s5  = "rUuSOrfOyAkjBP, aRvDhHRLuLxMGszvStp, fphUkcvHHZROXIzPbp);} while (KFcotscrG < ohRDDlPrlxhWr.length);return EiMWXrtylKsJNCN;}" fullword ascii
    $s6  = "function jSrCKKQkPv(ijKVgssWwusYEiuJ,XDhRadINidDknpreJfegyNv){return String.fromCharCode(ijKVgssWwusYEiuJ,XDhRadINidDknpreJfegyN" ascii
    $s7  = "function GmfgehrXNMZxeGMRes(FaNMrLDzluJCKaMsMKBGp,FPbxqqEjdBQGCWqQozKeJr,vvyWySQXpHYitAH){return String.fromCharCode(FaNMrLDzluJ" ascii
    $s8  = "function jSrCKKQkPv(ijKVgssWwusYEiuJ,XDhRadINidDknpreJfegyNv){return String.fromCharCode(ijKVgssWwusYEiuJ,XDhRadINidDknpreJfegyN" ascii
    $s9  = "function GmfgehrXNMZxeGMRes(FaNMrLDzluJCKaMsMKBGp,FPbxqqEjdBQGCWqQozKeJr,vvyWySQXpHYitAH){return String.fromCharCode(FaNMrLDzluJ" ascii
    $s10 = "function O(RJjGsILPBEwpYds){return String.fromCharCode(RJjGsILPBEwpYds);}" fullword ascii
    $s11 = "kcvHHZROXIzPbp = SZKrAMcbqlwO & 0xff;if (bRIWsUGVUWmBlqHtD == 64) EiMWXrtylKsJNCN += O(jzwUFAmrUuSOrfOyAkjBP);else if (yOXmx == " ascii
    $s12 = "RnPfwry<QanLGS.length;IzTRnPfwry++) {rwUObAZ+=WhrracSUnWR[QanLGS[IzTRnPfwry]];}return rwUObAZ.substring(3,rwUObAZ.length);}" fullword ascii
    $s13 = "64) EiMWXrtylKsJNCN += jSrCKKQkPv(jzwUFAmrUuSOrfOyAkjBP, aRvDhHRLuLxMGszvStp);else EiMWXrtylKsJNCN += GmfgehrXNMZxeGMRes(jzwUFAm" ascii
    $s14 = "var oZJwBF=function(){return TuKDuiYs().CreateObject(gfnStEsDHrWROfYtCA[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s15 = "function CklpwquirXC(){return xQzHtdOrRWHGDC(gfnStEsDHrWROfYtCA[8],[1,5,7],gfnStEsDHrWROfYtCA[9]);}" fullword ascii
    $s16 = "function OTcjVmGnxyufUt(){return xQzHtdOrRWHGDC(gfnStEsDHrWROfYtCA[12],[0,3,6],gfnStEsDHrWROfYtCA[13]);}" fullword ascii
    $s17 = "function sGJxTjXLlMNnHl(ohRDDlPrlxhWr) {var kvnTqmQkKCkzcvOaY = bkcOfiONtfhjNj.join(gfnStEsDHrWROfYtCA[6]);var jzwUFAmrUuSOrfOyA" ascii
    $s18 = "function eMCdqVpS(syqrYcRxVbUVzx,fqYbiXK) {var lVilBYruWenh=[gfnStEsDHrWROfYtCA[15]];syqrYcRxVbUVzx[lVilBYruWenh[0]](fqYbiXK,0x1" ascii
    $s19 = "function UpIqAlh(){return xQzHtdOrRWHGDC(gfnStEsDHrWROfYtCA[10],[2,4,8,10],gfnStEsDHrWROfYtCA[11]);}" fullword ascii
    $s20 = "function eMCdqVpS(syqrYcRxVbUVzx,fqYbiXK) {var lVilBYruWenh=[gfnStEsDHrWROfYtCA[15]];syqrYcRxVbUVzx[lVilBYruWenh[0]](fqYbiXK,0x1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}