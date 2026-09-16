rule sig_20160527_00c34e9b83c5a943f054624524c6795d {
  meta:
    description = "datamaliciousorder - file 20160527_00c34e9b83c5a943f054624524c6795d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da9466d2f412e801392c85e3dbb8ee7e8d6d5495e8625d1d624ca3c9e7313e8d"

  strings:
    $s1  = "function IeQAZjIz() {return WScript;}function PRywHcWkfRO(){return WRfbpsygzGenrA.ExpandEnvironmentStrings(byRaYkYwZcne())}" fullword ascii
    $s2  = "function vygMpVy(ItdQHyiIZeRBST,KgYkOMTmNhEhcVpqN){return ItdQHyiIZeRBST.charAt(KgYkOMTmNhEhcVpqN);}" fullword ascii
    $s3  = "jnuNC);else lXIxeZXtL += TBjwAtUGXzeGQySurK(iJFiegEZHOetCOMrBcDH, NTItjQqWpjnuNC, hgnMEYgvAanhCEl);} while (ffzeKeA < OiRNQIokPT" ascii
    $s4  = "push(\"t\");ZmkjnAUCvBfNOM.push(\"u\");ZmkjnAUCvBfNOM.push(\"v\");ZmkjnAUCvBfNOM.push(\"w\");ZmkjnAUCvBfNOM.push(\"x\");ZmkjnAUC" ascii
    $s5  = "function uwXRzQHUDMc(OiRNQIokPTflq) {var fYZHMpSqIAMkikWUba = ZmkjnAUCvBfNOM.join(bgNynMuZ[6]);var iJFiegEZHOetCOMrBcDH, NTItjQq" ascii
    $s6  = "function uwXRzQHUDMc(OiRNQIokPTflq) {var fYZHMpSqIAMkikWUba = ZmkjnAUCvBfNOM.join(bgNynMuZ[6]);var iJFiegEZHOetCOMrBcDH, NTItjQq" ascii
    $s7  = "64) lXIxeZXtL += MT(iJFiegEZHOetCOMrBcDH);else if (RVwzMJfqzmrP == 64) lXIxeZXtL += sRhuSSOZDajs(iJFiegEZHOetCOMrBcDH, NTItjQqWp" ascii
    $s8  = "flq.length);return lXIxeZXtL;}" fullword ascii
    $s9  = "function DnHuenYNAuntmL(){return ViAtgvTmUXvdQ(bgNynMuZ[10],[2,4,8,10],bgNynMuZ[11]);}" fullword ascii
    $s10 = "function TBjwAtUGXzeGQySurK(aPFtLDOZOJFBo,cxYXrDiPzHakuV,loPFgj){return String.fromCharCode(aPFtLDOZOJFBo,cxYXrDiPzHakuV,loPFgj)" ascii
    $s11 = "function ViAtgvTmUXvdQ(DMNbNWdoSmV,xJRRDmGY,KlDGcjBMshrb){kNWbnuzxvZo=DMNbNWdoSmV.split(KlDGcjBMshrb);BpjGIxpA = bgNynMuZ[14];fo" ascii
    $s12 = "var WRfbpsygzGenrA=function(){return IeQAZjIz().CreateObject(bgNynMuZ[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "function OHqCLcIJ(){return ViAtgvTmUXvdQ(bgNynMuZ[12],[0,3,6],bgNynMuZ[13]);}" fullword ascii
    $s14 = "function KKIEfRZ(zfOcbcQHjyAPu,vaofLbhzzCmHnLVxlTFgEZ){return zfOcbcQHjyAPu.indexOf(vaofLbhzzCmHnLVxlTFgEZ);}" fullword ascii
    $s15 = "var tzAjkI=function(){return new ActiveXObject(bgNynMuZ[0]);}();" fullword ascii
    $s16 = "function ViAtgvTmUXvdQ(DMNbNWdoSmV,xJRRDmGY,KlDGcjBMshrb){kNWbnuzxvZo=DMNbNWdoSmV.split(KlDGcjBMshrb);BpjGIxpA = bgNynMuZ[14];fo" ascii
    $s17 = "function MT(lUpuUQGVKsIectgWPxx){return String.fromCharCode(lUpuUQGVKsIectgWPxx);}" fullword ascii
    $s18 = "function ZzzgMRgEWVHCn(vGVJOJo,XyvAvOFW) {var nzxnBDwbe=[bgNynMuZ[15]];vGVJOJo[nzxnBDwbe[0]](XyvAvOFW,0x1,0x0)}" fullword ascii
    $s19 = "var nmlNST = tzAjkI.createtextfile(WRfbpsygzGenrA.ExpandEnvironmentStrings(bgNynMuZ[2]+bgNynMuZ[3])+String.fromCharCode(92)+bgNy" ascii
    $s20 = "function byRaYkYwZcne(){return ViAtgvTmUXvdQ(bgNynMuZ[8],[1,5,7],bgNynMuZ[9]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}