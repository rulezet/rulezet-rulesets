rule sig_20160527_fb6122c380910ad3be34949261ca437d {
  meta:
    description = "datamaliciousorder - file 20160527_fb6122c380910ad3be34949261ca437d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae4a791cf82830a099b270726727f17259abccab76fb6213975a0f2918cce837"

  strings:
    $s1  = "function qVBFcbjX() {return WScript;}function aKIkezchsSrQeU(){return gjOLts.ExpandEnvironmentStrings(Glnle())}" fullword ascii
    $s2  = "function ajIsRRu(oXuwmHtOFaBeFtzpoaAAL,qlQYPTrXBFDqnKvcHNyKez){return oXuwmHtOFaBeFtzpoaAAL.charAt(qlQYPTrXBFDqnKvcHNyKez);}" fullword ascii
    $s3  = "function WlGgF(CpAaFzN,vtyepdcfa,bkhVABnzfrK){LcOodqhVz=CpAaFzN.split(bkhVABnzfrK);kXxelf = lXvULNb[14];for(EFolKilcWLae=0;EFolK" ascii
    $s4  = "function Glnle(){return WlGgF(lXvULNb[8],[1,5,7],lXvULNb[9]);}" fullword ascii
    $s5  = "var BdgWDuJBnkk = PTGtnnIgSejuF.createtextfile(gjOLts.ExpandEnvironmentStrings(lXvULNb[2]+lXvULNb[3])+String.fromCharCode(92)+lX" ascii
    $s6  = "function EaTbmJLUifnBdBLGgcddyaD(LkJaWkYFdWcSSU,IpiqyfpdqzkisqCiwlxCfCl,pmUQLgwJsEAaoXtYDlqW){return String.fromCharCode(LkJaWkY" ascii
    $s7  = "function WlGgF(CpAaFzN,vtyepdcfa,bkhVABnzfrK){LcOodqhVz=CpAaFzN.split(bkhVABnzfrK);kXxelf = lXvULNb[14];for(EFolKilcWLae=0;EFolK" ascii
    $s8  = "var gjOLts=function(){return qVBFcbjX().CreateObject(lXvULNb[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s9  = "function CSuudMFSnIEhMv(WjembkvkjDJET) {var OmGnUYBpbDTUBfkjrNoH = adBWodlUbuRaB.join(lXvULNb[6]);var vCQkdnbdloK, SwYTecUO, xBN" ascii
    $s10 = "function IzvJMqCihoEPgGzGGCIJmS(dfXgYNngEY,JmLcDJd){return dfXgYNngEY.indexOf(JmLcDJd);}" fullword ascii
    $s11 = "function INuTIJmU(HrQimIezhNp,MZdKoefbex){return String.fromCharCode(HrQimIezhNp,MZdKoefbex);}" fullword ascii
    $s12 = "function zsPSBPKHsG(){return WlGgF(lXvULNb[12],[0,3,6],lXvULNb[13]);}" fullword ascii
    $s13 = "var PTGtnnIgSejuF=function(){return new ActiveXObject(lXvULNb[0]);}();" fullword ascii
    $s14 = "KhJdyvws);} while (HzKohpt < WjembkvkjDJET.length);return vgQog;}" fullword ascii
    $s15 = "function EaTbmJLUifnBdBLGgcddyaD(LkJaWkYFdWcSSU,IpiqyfpdqzkisqCiwlxCfCl,pmUQLgwJsEAaoXtYDlqW){return String.fromCharCode(LkJaWkY" ascii
    $s16 = "ilcWLae<vtyepdcfa.length;EFolKilcWLae++) {kXxelf+=LcOodqhVz[vtyepdcfa[EFolKilcWLae]];}return kXxelf.substring(3,kXxelf.length);}" ascii
    $s17 = " = EpcWGJVodXvup>> 8 & 0xff;xBNYJbFKhJdyvws = EpcWGJVodXvup & 0xff;if (QhrOX == 64) vgQog += pR(vCQkdnbdloK);else if (glgzHjJrEo" ascii
    $s18 = "vULNb[4],true);" fullword ascii
    $s19 = "function SmVuDEzmrnifGy(){return WlGgF(lXvULNb[10],[2,4,8,10],lXvULNb[11]);}" fullword ascii
    $s20 = "function ayVuvYVxvhpo(OQPgoQex,gQrDoKL) {var RdPIWrQstDBKCl=[lXvULNb[15]];OQPgoQex[RdPIWrQstDBKCl[0]](gQrDoKL,0x1,0x0)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}