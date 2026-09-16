rule sig_20160523_25db6d79fde895b6671c83ac55871e3a {
  meta:
    description = "datamaliciousorder - file 20160523_25db6d79fde895b6671c83ac55871e3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b794d36828a3d9af0767c0f2d7817b9ea540d7fcf9b0961ee308ea4ff117ae20"

  strings:
    $s1  = "function ufsugeBpyv(IMzqFIPA,JDzmNvijiHUE) {IMzqFIPA.Run(JDzmNvijiHUE, 0x1, 0x0);}" fullword ascii
    $s2  = "function RzXagXTn(qnfse) {var OfuKsTYS=KwsBPNtOzNQDfv[13];for(var rSjOC=0;rSjOC<qnfse;rSjOC++){aFjsR+=OfuKsTYS.charAt(Math.floor" ascii
    $s3  = "function RzXagXTn(qnfse) {var OfuKsTYS=KwsBPNtOzNQDfv[13];for(var rSjOC=0;rSjOC<qnfse;rSjOC++){aFjsR+=OfuKsTYS.charAt(Math.floor" ascii
    $s4  = "svHbX.length;FIfTHKer++) {dORnrJp+=pfbrG[lsvHbX[FIfTHKer]];}return dORnrJp.substring(3,dORnrJp.length);}" fullword ascii
    $s5  = "function ottGBQWY(RqtcneCPv) {RqtcneCPv.type=1;}" fullword ascii
    $s6  = "function JmgOzoE(){return Math.random();}" fullword ascii
    $s7  = "function EFeKo(rIytwcFC,mLjdF,HOHSoBxSEZ){jIZl(rIytwcFC);ottGBQWY(rIytwcFC);QQLtOaN(rIytwcFC,mLjdF);AfOQxxZOj(rIytwcFC);lXkW(rIy" ascii
    $s8  = "false);SioFFxk.send();}" fullword ascii
    $s9  = "function irHtg(PuWOQX){return new ActiveXObject(PuWOQX);}" fullword ascii
    $s10 = "function nWdn(oWIYkl,SioFFxk){ytXk = KwsBPNtOzNQDfv[10].split(KwsBPNtOzNQDfv[11]);SioFFxk.open(ytXk[0]+ytXk[2]+ytXk[3], oWIYkl, " ascii
    $s11 = "function lcibJ(KdVfkaCc,lsvHbX,xxpghDoLx){pfbrG=KdVfkaCc.split(xxpghDoLx);dORnrJp = KwsBPNtOzNQDfv[12];for(FIfTHKer=0;FIfTHKer<l" ascii
    $s12 = "function lcibJ(KdVfkaCc,lsvHbX,xxpghDoLx){pfbrG=KdVfkaCc.split(xxpghDoLx);dORnrJp = KwsBPNtOzNQDfv[12];for(FIfTHKer=0;FIfTHKer<l" ascii
    $s13 = "function lXkW(fzsBkQx,XrUfVTj) {fzsBkQx.saveToFile(XrUfVTj, 2);}" fullword ascii
    $s14 = "if(QmRr>IgEjD.length) break;" fullword ascii
    $s15 = "function QQLtOaN(NHyt,HHdDG) {NHyt.write(HHdDG);}" fullword ascii
    $s16 = "function mKYyhGu() {var SWDq=100000;var Hkldsb = 100;return JmgOzoE()*(SWDq-Hkldsb)+Hkldsb;}" fullword ascii
    $s17 = "function tHHISSa(PJOPC) {PJOPC.close();}" fullword ascii
    $s18 = "function AfOQxxZOj(wJGWVP) {var XulQRRlLUW=[];wJGWVP.position=XulQRRlLUW.length*(7223884-328);}" fullword ascii
    $s19 = "function EFeKo(rIytwcFC,mLjdF,HOHSoBxSEZ){jIZl(rIytwcFC);ottGBQWY(rIytwcFC);QQLtOaN(rIytwcFC,mLjdF);AfOQxxZOj(rIytwcFC);lXkW(rIy" ascii
    $s20 = "function jIZl(fJxmtA) {fJxmtA.open();}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}