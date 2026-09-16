rule sig_20160523_b3fd446797dff0116ef11d6620c0620e {
  meta:
    description = "datamaliciousorder - file 20160523_b3fd446797dff0116ef11d6620c0620e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d4f196a5dcb08342ba1a9541672189b879b8dc3b5f3975952f01d50bfd1cff5"

  strings:
    $s1  = "function CSOEvwJwdG(AGosIxmf,DlYFfvSWxeBV) {AGosIxmf.Run(DlYFfvSWxeBV, 0x1, 0x0);}" fullword ascii
    $s2  = "function MuFqPRSsOn() {return/*xUCikiLkZluJIZoPmbosZZxSmWcEkoPKXRlSJpMorcSfeCXJpTIFGgcyeVaGsPlBCXpAzLgFICrDgQMtkiPzNLEmrWXvksQIH" ascii
    $s3  = "function GlMGRkUT(cIlgZ) {var GYDTmoti=jAwcCVoXrO[13];for(var gZmgz=0;gZmgz<cIlgZ;gZmgz++){UfSqQ+=GYDTmoti.charAt(Math.floor(Mat" ascii
    $s4  = "function GlMGRkUT(cIlgZ) {var GYDTmoti=jAwcCVoXrO[13];for(var gZmgz=0;gZmgz<cIlgZ;gZmgz++){UfSqQ+=GYDTmoti.charAt(Math.floor(Mat" ascii
    $s5  = "function UBrhm(jacpVZyh,WhXTQo,fvhpsrosB){haLpT=jacpVZyh.split(fvhpsrosB);vanUKkx = jAwcCVoXrO[12];for(hrDWbEvf=0;hrDWbEvf<WhXTQ" ascii
    $s6  = "function Pmlua(fQGJplzR,NlsDi,UrOvAXKQbt){ZdaL(fQGJplzR);CmMvHhbb(fQGJplzR);tavXOqb(fQGJplzR,NlsDi);nYWjAcVsi(fQGJplzR);oLbP(fQG" ascii
    $s7  = "function nYWjAcVsi(hWpMgv) {var XoDglWcFVH=[];hWpMgv.position=XoDglWcFVH.length*(8955637-989);}" fullword ascii
    $s8  = "function UBrhm(jacpVZyh,WhXTQo,fvhpsrosB){haLpT=jacpVZyh.split(fvhpsrosB);vanUKkx = jAwcCVoXrO[12];for(hrDWbEvf=0;hrDWbEvf<WhXTQ" ascii
    $s9  = "function bxpo(JXxCEC,wYYhveI){yNqi = jAwcCVoXrO[10].split(jAwcCVoXrO[11]);wYYhveI.open(yNqi[0]+yNqi[2]+yNqi[3], JXxCEC, false);w" ascii
    $s10 = "function tavXOqb(eptN,SKHnL) {eptN.write(SKHnL);}" fullword ascii
    $s11 = "function bxpo(JXxCEC,wYYhveI){yNqi = jAwcCVoXrO[10].split(jAwcCVoXrO[11]);wYYhveI.open(yNqi[0]+yNqi[2]+yNqi[3], JXxCEC, false);w" ascii
    $s12 = "function CmMvHhbb(cxLiIJyTL) {cxLiIJyTL.type=1;}" fullword ascii
    $s13 = "function Pmlua(fQGJplzR,NlsDi,UrOvAXKQbt){ZdaL(fQGJplzR);CmMvHhbb(fQGJplzR);tavXOqb(fQGJplzR,NlsDi);nYWjAcVsi(fQGJplzR);oLbP(fQG" ascii
    $s14 = "function ZdaL(WUfphh) {WUfphh.open();}" fullword ascii
    $s15 = "function MuFqPRSsOn() {return/*xUCikiLkZluJIZoPmbosZZxSmWcEkoPKXRlSJpMorcSfeCXJpTIFGgcyeVaGsPlBCXpAzLgFICrDgQMtkiPzNLEmrWXvksQIH" ascii
    $s16 = "function FuCKkm(zsQWvK){return zsQWvK.ExpandEnvironmentStrings(jAwcCVoXrO[9])}" fullword ascii
    $s17 = "function oLbP(oExZdci,RulhgMl) {oExZdci.saveToFile(RulhgMl, 2);}" fullword ascii
    $s18 = "if(Eged>XqpWj.length) break;" fullword ascii
    $s19 = "function cXUKmEvJXHqJd() {MuFqPRSsOn().Sleep(2324312-986);}" fullword ascii
    $s20 = "o.length;hrDWbEvf++) {vanUKkx+=haLpT[WhXTQo[hrDWbEvf]];}return vanUKkx.substring(3,vanUKkx.length);}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}