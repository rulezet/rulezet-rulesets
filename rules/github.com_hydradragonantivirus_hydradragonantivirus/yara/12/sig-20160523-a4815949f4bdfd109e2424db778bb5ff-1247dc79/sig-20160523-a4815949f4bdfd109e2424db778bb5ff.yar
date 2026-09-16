rule sig_20160523_a4815949f4bdfd109e2424db778bb5ff {
  meta:
    description = "datamaliciousorder - file 20160523_a4815949f4bdfd109e2424db778bb5ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9709c97b29ef0fba70805b704bafdfb6f02508498267fc924454941a0115ffa7"

  strings:
    $s1  = "function qDNozMqLRU(nJhZiUQy,iBHrPsackDLC) {nJhZiUQy.Run(iBHrPsackDLC, 0x1, 0x0);}" fullword ascii
    $s2  = "function JtPwXIIn(Xzdyj) {var XmXFGTZI=FbPPQcqVwMkVelteeF[2];for(var GmysC=0;GmysC<Xzdyj;GmysC++){aLhxv+=XmXFGTZI.charAt(Math.fl" ascii
    $s3  = "function JtPwXIIn(Xzdyj) {var XmXFGTZI=FbPPQcqVwMkVelteeF[2];for(var GmysC=0;GmysC<Xzdyj;GmysC++){aLhxv+=XmXFGTZI.charAt(Math.fl" ascii
    $s4  = "jyUfkl, false);hAmMkDL.send();}" fullword ascii
    $s5  = "oor(Math.random()*XmXFGTZI.length));}return aLhxv;}" fullword ascii
    $s6  = "function autptYfTH(fOfPvh) {var toYtzdtlRH=[];fOfPvh.position=toYtzdtlRH.length*(4312582-562);}" fullword ascii
    $s7  = "function AtbBWtvB(xCHLURoRG) {xCHLURoRG.type=1;}" fullword ascii
    $s8  = "function GGnTC(xbzLpRZF,pVmia,YDUBlRMyvs){pdax(xbzLpRZF);AtbBWtvB(xbzLpRZF);KvfxhHk(xbzLpRZF,pVmia);autptYfTH(xbzLpRZF);LUlY(xbz" ascii
    $s9  = "function SdlsP(rPxNCr){return new ActiveXObject(rPxNCr);}" fullword ascii
    $s10 = "function KvfxhHk(MFdu,rdptD) {MFdu.write(rdptD);}" fullword ascii
    $s11 = "function usjBblJiP(HarCVDWCL,XnXTiXx,MHeoitni){" fullword ascii
    $s12 = "function JGVqzLU(BWTyf) {BWTyf.close();}" fullword ascii
    $s13 = "function jWLa(jyUfkl,hAmMkDL){infI = FbPPQcqVwMkVelteeF[11].split(FbPPQcqVwMkVelteeF[12]);hAmMkDL.open(infI[0]+infI[2]+infI[3], " ascii
    $s14 = "if (dDqCRvK==0) break;" fullword ascii
    $s15 = "try{dDqCRvK=usjBblJiP(RBjKa[bNcO], KlkWKjo() + FbPPQcqVwMkVelteeF[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function NbiXCz(rPxNCr){return rPxNCr.ExpandEnvironmentStrings(FbPPQcqVwMkVelteeF[10])}" fullword ascii
    $s17 = "function UGDwA(MvyrbyZN,YRlFBg,TmkviyVqP){QGbDX=MvyrbyZN.split(TmkviyVqP);nnRwqCC = FbPPQcqVwMkVelteeF[13];for(IiUbIVOB=0;IiUbIV" ascii
    $s18 = "function jWLa(jyUfkl,hAmMkDL){infI = FbPPQcqVwMkVelteeF[11].split(FbPPQcqVwMkVelteeF[12]);hAmMkDL.open(infI[0]+infI[2]+infI[3], " ascii
    $s19 = "function vmalJOe(){return Math.random();}" fullword ascii
    $s20 = "OB<YRlFBg.length;IiUbIVOB++) {nnRwqCC+=QGbDX[YRlFBg[IiUbIVOB]];}return nnRwqCC.substring(3,nnRwqCC.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}