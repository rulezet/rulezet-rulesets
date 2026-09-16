rule sig_20160530_132db01ea2e1143db4bcd1e972872b05 {
  meta:
    description = "datamaliciousorder - file 20160530_132db01ea2e1143db4bcd1e972872b05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff47abb6eb4a226ef327ff7f046c7387171c3d4feb51149e1179ff9d9e4e7daf"

  strings:
    $s1  = "var ENVRBDoBS=function(){return WScript.CreateObject(KcJvHm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function fhMCYDTi(omJWhPypQPVUJSWGxvTOR,FHajnNcXanFFhNnaavpwnJeW){return omJWhPypQPVUJSWGxvTOR.charAt(FHajnNcXanFFhNnaavpwnJeW);" ascii
    $s3  = "function fhMCYDTi(omJWhPypQPVUJSWGxvTOR,FHajnNcXanFFhNnaavpwnJeW){return omJWhPypQPVUJSWGxvTOR.charAt(FHajnNcXanFFhNnaavpwnJeW);" ascii
    $s4  = "var GSKiS=function(){return new ActiveXObject(KcJvHm[1]);}();" fullword ascii
    $s5  = "f;KaMhokNvekTbDZbNNsbvIy = ZWEJgbFpBbTVpnpyO & 0xff;if (FkNRJtGewgxPjFLKnA == 64) WlVWxqtgpeqGNJ += dU(XfYIFOzXgEFgMk);else if (" ascii
    $s6  = "function jZfuc(ThwYG,IWEnn,AVcQzls){NAwupIf=ThwYG.split(AVcQzls);tRKOpBKLasaYG = KcJvHm[0];for(tjUsLkxCB=0;tjUsLkxCB<IWEnn.lengt" ascii
    $s7  = "function VsMsQXtIrwCS(){return jZfuc(KcJvHm[13],[0,3,6],KcJvHm[14]);}" fullword ascii
    $s8  = "function VZithPZhGvSZNwf(vjHFt,fEJjlJbWrjlarQhpSO){return vjHFt.indexOf(fEJjlJbWrjlarQhpSO);}" fullword ascii
    $s9  = "function xjWce(){return jZfuc(KcJvHm[9],[1,5,7],KcJvHm[10]);}" fullword ascii
    $s10 = "function jZfuc(ThwYG,IWEnn,AVcQzls){NAwupIf=ThwYG.split(AVcQzls);tRKOpBKLasaYG = KcJvHm[0];for(tjUsLkxCB=0;tjUsLkxCB<IWEnn.lengt" ascii
    $s11 = "function DfaSlOxddzDUMy(){return jZfuc(KcJvHm[11],[2,4,8,10],KcJvHm[12]);}" fullword ascii
    $s12 = "function MsQsyUbnkpWzlQ(ITXFfFrAZa,CxtSUjbGdNdbltXGzHHO){return String.fromCharCode(ITXFfFrAZa,CxtSUjbGdNdbltXGzHHO);}" fullword ascii
    $s13 = "EahgOZBvoOLDGRZdLpqriDBL == 64) WlVWxqtgpeqGNJ += MsQsyUbnkpWzlQ(XfYIFOzXgEFgMk, VVPFfFaGZfpLyfaSqOBRZdKB);else WlVWxqtgpeqGNJ +" ascii
    $s14 = "function IPzareMuztto(){return ENVRBDoBS.ExpandEnvironmentStrings(xjWce())}" fullword ascii
    $s15 = "function PoXExKfTV(nQndGmcXConEL) {var GaJsAGeUO = JgFYkhGBksJDanZZsPCvC.join(KcJvHm[7]);var XfYIFOzXgEFgMk, VVPFfFaGZfpLyfaSqOB" ascii
    $s16 = "function dU(jaTQkozOfsQuhsfGCz){return String.fromCharCode(jaTQkozOfsQuhsfGCz);}" fullword ascii
    $s17 = "h;tjUsLkxCB++) {tRKOpBKLasaYG+=NAwupIf[IWEnn[tjUsLkxCB]];}return tRKOpBKLasaYG.substring(3,tRKOpBKLasaYG.length);}" fullword ascii
    $s18 = "function UcRNiTufUrZEXa(QhqSZvnREwC,leMUQ) {var CheTBe=[KcJvHm[15]];QhqSZvnREwC[CheTBe[0]]" fullword ascii
    $s19 = "var TNIGdGe = GSKiS.createtextfile(ENVRBDoBS.ExpandEnvironmentStrings(KcJvHm[3]+KcJvHm[4])+String.fromCharCode(92)+KcJvHm[5],tru" ascii
    $s20 = "= LcaxfZo(XfYIFOzXgEFgMk, VVPFfFaGZfpLyfaSqOBRZdKB, KaMhokNvekTbDZbNNsbvIy);} while (cQUqcQfNBHBZhK < nQndGmcXConEL.length);retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}