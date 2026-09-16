rule sig_20160523_973f83989cf34c38e769f35b3c473528 {
  meta:
    description = "datamaliciousorder - file 20160523_973f83989cf34c38e769f35b3c473528.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9923ad92d52a02c789ee87f299a27bb78199da606177ae65b2d21e31ef666bf0"

  strings:
    $s1  = "function pBAicEdU(pIBwy) {var XSpDbQJO=phbwQw[13];for(var UzYJK=0;UzYJK<pIBwy;UzYJK++){RuNow+=XSpDbQJO.charAt(Math.floor(Math.ra" ascii
    $s2  = "function pBAicEdU(pIBwy) {var XSpDbQJO=phbwQw[13];for(var UzYJK=0;UzYJK<pIBwy;UzYJK++){RuNow+=XSpDbQJO.charAt(Math.floor(Math.ra" ascii
    $s3  = "function uzxEvXAlPN() {return/*PuUMaWNDFCEfwWnDVnkeLvHhBVggGSzuwaoDodxbJyLqADtIaSDsHNqVZPTPhEcXRESHDbjVUQWcxXcGIkquHQZqAzmGqRzBZ" ascii
    $s4  = "function NGiVIRqMGv(wDkYMtRr,yxcuugLfbSOT) {wDkYMtRr.Run(yxcuugLfbSOT, 0x1, 0x0);}" fullword ascii
    $s5  = "ndom()*XSpDbQJO.length));}return RuNow;}" fullword ascii
    $s6  = "function slHHldyiLBiaZ() {uzxEvXAlPN().Sleep(2337966-231);}" fullword ascii
    $s7  = "function qDQa(wSiwLZ,XFQOouC){ffCc = phbwQw[10].split(phbwQw[11]);XFQOouC.open(ffCc[0]+ffCc[2]+ffCc[3], wSiwLZ, false);XFQOouC.s" ascii
    $s8  = "function QpeEBWeO(OlbLoeMCm) {OlbLoeMCm.type=1;}" fullword ascii
    $s9  = "function agnfd(vZhvPrlc,dpZzB,rbBOCZaJLc){yVHp(vZhvPrlc);QpeEBWeO(vZhvPrlc);czBUiFL(vZhvPrlc,dpZzB);gZsFOnigq(vZhvPrlc);GVfr(vZh" ascii
    $s10 = "function KZWJmZl() {var mdEY=100000;var JrAyLg = 100;return tDGxZMD()*(mdEY-JrAyLg)+JrAyLg;}" fullword ascii
    $s11 = "function tDGxZMD(){return Math.random();}" fullword ascii
    $s12 = "function PnRzq(jUzjohwa,QPpesI,DzpoiqpZq){Icoap=jUzjohwa.split(DzpoiqpZq);eiXWmqI = phbwQw[12];for(xrLxPUMR=0;xrLxPUMR<QPpesI.le" ascii
    $s13 = "function yVHp(seMtMW) {seMtMW.open();}" fullword ascii
    $s14 = "function PnRzq(jUzjohwa,QPpesI,DzpoiqpZq){Icoap=jUzjohwa.split(DzpoiqpZq);eiXWmqI = phbwQw[12];for(xrLxPUMR=0;xrLxPUMR<QPpesI.le" ascii
    $s15 = "function pTPXzcO(lROvl) {lROvl.close();}" fullword ascii
    $s16 = "if(KmVp>xGYxL.length) break;" fullword ascii
    $s17 = "function jgKKtv(COKjmn){return COKjmn.ExpandEnvironmentStrings(phbwQw[9])}" fullword ascii
    $s18 = "function GVfr(PPpNFOz,fvejikE) {PPpNFOz.saveToFile(fvejikE, 2);}" fullword ascii
    $s19 = "function DwAFL(COKjmn){return new ActiveXObject(COKjmn);}" fullword ascii
    $s20 = "function agnfd(vZhvPrlc,dpZzB,rbBOCZaJLc){yVHp(vZhvPrlc);QpeEBWeO(vZhvPrlc);czBUiFL(vZhvPrlc,dpZzB);gZsFOnigq(vZhvPrlc);GVfr(vZh" ascii

  condition:
    uint16(0) == 0x1927 and
    8 of them
}