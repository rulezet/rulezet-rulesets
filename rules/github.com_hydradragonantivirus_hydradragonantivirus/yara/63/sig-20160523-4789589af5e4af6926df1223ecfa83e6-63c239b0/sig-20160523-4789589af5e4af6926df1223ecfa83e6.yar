rule sig_20160523_4789589af5e4af6926df1223ecfa83e6 {
  meta:
    description = "datamaliciousorder - file 20160523_4789589af5e4af6926df1223ecfa83e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "236bc8dfc4e2fec1a9437dfae856eb92c92963012966e6790dfafee013b4ed33"

  strings:
    $s1  = "function HkuOMitnwR(kVDhxgIL,PIIJPQytICNI) {kVDhxgIL.Run(PIIJPQytICNI, 0x1, 0x0);}" fullword ascii
    $s2  = "function mXsptUHg(Gktpk) {var gUZcLVMe=gdzvMYAZLRP[13];for(var juVpU=0;juVpU<Gktpk;juVpU++){MZwrP+=gUZcLVMe.charAt(Math.floor(Ma" ascii
    $s3  = "function mXsptUHg(Gktpk) {var gUZcLVMe=gdzvMYAZLRP[13];for(var juVpU=0;juVpU<Gktpk;juVpU++){MZwrP+=gUZcLVMe.charAt(Math.floor(Ma" ascii
    $s4  = "function FpCQsUQtCf() {return/*FmIxdtbNTjROkfwVYyXZCeDcAJvwCJoSopBPkGZgjzpUQZHxyulcJaBugmtiYktroUtvQBBWNhOxxPnmVFtttWhyngFlUNIoH" ascii
    $s5  = "function kLwVkPZVR(oMbChx) {var kDqSeFVGzA=[];oMbChx.position=kDqSeFVGzA.length*(9522707-720);}" fullword ascii
    $s6  = "function amMMyZu() {var BSPm=100000;var rDKknw = 100;return oRuWNrP()*(BSPm-rDKknw)+rDKknw;}" fullword ascii
    $s7  = "function DZNW(HgEJIo,iKgHGPg){oLnV = gdzvMYAZLRP[10].split(gdzvMYAZLRP[11]);iKgHGPg.open(oLnV[0]+oLnV[2]+oLnV[3], HgEJIo, false)" ascii
    $s8  = "if(jHqh>Hkwko.length) break;" fullword ascii
    $s9  = "function uzEt(COSvEF) {COSvEF.open();}" fullword ascii
    $s10 = "function GwjZo(nCQqtJ){return new ActiveXObject(nCQqtJ);}" fullword ascii
    $s11 = "function OiLyG(zgxkRJkg,wklyEJ,FpVrDSjMD){gxXLc=zgxkRJkg.split(FpVrDSjMD);viwIDBK = gdzvMYAZLRP[12];for(FehiLjir=0;FehiLjir<wkly" ascii
    $s12 = "function xZjDYuBH(pfmdZjGhY) {pfmdZjGhY.type=1;}" fullword ascii
    $s13 = "th.random()*gUZcLVMe.length));}return MZwrP;}" fullword ascii
    $s14 = "function DZNW(HgEJIo,iKgHGPg){oLnV = gdzvMYAZLRP[10].split(gdzvMYAZLRP[11]);iKgHGPg.open(oLnV[0]+oLnV[2]+oLnV[3], HgEJIo, false)" ascii
    $s15 = "function UxqOIhWzKNcJd() {FpCQsUQtCf().Sleep(2330466-725);}" fullword ascii
    $s16 = "function dTXqrOd(xRVWW) {xRVWW.close();}" fullword ascii
    $s17 = "function KkpGjVY(cCZX,sJGDX) {cCZX.write(sJGDX);}" fullword ascii
    $s18 = "function oRuWNrP(){return Math.random();}" fullword ascii
    $s19 = "function kOdC(ZwpsdgF,TezDJgB) {ZwpsdgF.saveToFile(TezDJgB, 2);}" fullword ascii
    $s20 = "function OiLyG(zgxkRJkg,wklyEJ,FpVrDSjMD){gxXLc=zgxkRJkg.split(FpVrDSjMD);viwIDBK = gdzvMYAZLRP[12];for(FehiLjir=0;FehiLjir<wkly" ascii

  condition:
    uint16(0) == 0x1f27 and
    8 of them
}