rule sig_20160524_f23082e030926c21d1707cb17e56ce53 {
  meta:
    description = "datamaliciousorder - file 20160524_f23082e030926c21d1707cb17e56ce53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "796a1899b0fa95aa115d6f603be49f3d89ef1bf7e28aa16f7e0f437a9beda7c1"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "MHRuUkpRO[0]);}();var XIfbwZewmYl=function(){return new ActiveXObject(\"WScript.Shell\");}();var UbSMuOgYVKokXK = LyrxoMMHRuUkpR" ascii
    $s3  = "cXwmKIgjz(PMuSwAMP,jfBNfPFMQosi) {PMuSwAMP.Run(jfBNfPFMQosi, 0x1, 0x0);}function mNaxvJr() {var OCfs=100000;var JycIUD = 100;ret" ascii
    $s4  = "();XIfbwZewmYl.Run(YydldwboUFy[0]+wFzvCzAh,0x1,0x0);}DhvXELQhUBe();function (kiVRYRR) {return new ActiveXObject(kiVRYRR);}" fullword ascii
    $s5  = "OkmYalzOWAjWvcVfPqODVntZgsOGnDEjIuVTj*/WScript;}function jIOasxDND(RKxqWw) {var XDpxFOcYmW=[];RKxqWw.position=XDpxFOcYmW.length*" ascii
    $s6  = "uUN++){WgJMt+=iBMeqzks.charAt(Math.floor(Math.random()*iBMeqzks.length));}return WgJMt;}function diVgpnkKUhQukq(UvdLayQSmPqJkf) " ascii
    $s7  = "romCharCode(92) + lkMqrLv;var YnrYH = function(){return new ActiveXObject(QqYXO(wlVAFWGmWpxFsDizfP[5],[0,2,4],wlVAFWGmWpxFsDizfP" ascii
    $s8  = "reak;var tVIjFDCdh=hJVoy[QFgq];var lkMqrLv=mNaxvJr() + wlVAFWGmWpxFsDizfP[2];var ZUMRzrqk=155-154;var IJdmTsciW = function(){ret" ascii
    $s9  = "(508811-140);}function OMky(EXsucqb,infcMQY) {EXsucqb.saveToFile(infcMQY, 2);}function PFRjeKT(wpBcW) {wpBcW.close();}function l" ascii
    $s10 = "1]);sIyNhQf.open(SsNQ[0]+SsNQ[2]+SsNQ[3], gKnVyD, false);sIyNhQf.send();}function QqYXO(QMunholf,ohiIKy,wOtRMONqq){fuaqh=QMunhol" ascii
    $s11 = "9])}function FXCjF(IUTzWkmn,sjGtb,cTPDAracQS){IUTzWkmn.open();QSHfuvaV(IUTzWkmn);pfroUwT(IUTzWkmn,sjGtb);jIOasxDND(IUTzWkmn);OMk" ascii
    $s12 = "y(IUTzWkmn,cTPDAracQS);PFRjeKT(IUTzWkmn);}function XdHO(gKnVyD,sIyNhQf){SsNQ = wlVAFWGmWpxFsDizfP[10].split(wlVAFWGmWpxFsDizfP[1" ascii
    $s13 = "TscDH]];}return rXgoRaP.substring(3,rXgoRaP.length);}function NrwiiYcwDtytw() {vOEbzaHPhk().Sleep(4473-806);}function CPUofrU(){" ascii
    $s14 = "urn CPUofrU()*(OCfs-JycIUD)+JycIUD;}function XsFHObCc(aNXGG) {var iBMeqzks=wlVAFWGmWpxFsDizfP[13];for(var QCuUN=0;QCuUN<aNXGG;QC" ascii
    $s15 = "[6]));}();XdHO(tVIjFDCdh,YnrYH);if (YnrYH.status == 100+100) {var lniPOQI = function() {return new ActiveXObject(QqYXO(wlVAFWGmW" ascii
    $s16 = "e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function DhvXELQhUBe() {var RdfkQbk;var iTkgqj=function(){return new ActiveXOb" ascii
    $s17 = "{return new ActiveXObject(UvdLayQSmPqJkf);}');var YydldwboUFy=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"]" ascii
    $s18 = "gYVKokXK;RdfkQbk = iTkgqj.OpenTextFile(wFzvCzAh,2,true);RdfkQbk.Write('var wlVAFWGmWpxFsDizfP=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f" ascii
    $s19 = "NrwiiYcwDtytw();var hJVoy = [wlVAFWGmWpxFsDizfP[0], wlVAFWGmWpxFsDizfP[1]];var QFgq=583-583;while(true) {if(QFgq>hJVoy.length) b" ascii
    $s20 = "V,CgTGU) {GJZV.write(CgTGU);}function vOEbzaHPhk() {return/*uxWchwZOOLVgGPNpAGhbPIiAqUvywOYgYoxloTWWkBaaeLOJOuRGFcoewHKPEGjWWZrn" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}