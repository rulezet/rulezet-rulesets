rule sig_20160524_3fd71d54a133027026a8086ef8107384 {
  meta:
    description = "datamaliciousorder - file 20160524_3fd71d54a133027026a8086ef8107384.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d2601e50f78b17bb291f26ae4b869795450d21592c55e38c2bf828a94fcff7"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "EmKNTK.Run(GadaSfRBShxf, 0x1, 0x0);}function szTZtoo() {var rNwy=100000;var anpXhe = 100;return wbuYPKP()*(rNwy-anpXhe)+anpXhe;}" ascii
    $s3  = "K=function(){return new ActiveXObject(\"WScript.Shell\");}();var XVdYdkdaVqq = opEoGNnctQDVj[1]+17079+opEoGNnctQDVj[2];var LGfck" ascii
    $s4  = "*/WScript;}function tOlskHTiD(sntoTb) {var JLIlrKKxaE=[];sntoTb.position=JLIlrKKxaE.length*(9352998-705);}function yQYk(VUUVAQb," ascii
    $s5  = "function LJqYcgGf(fnHlm) {var CzCqYMOI=hrrvGdVJhdWgFdjgRaIoCB[13];for(var YAifB=0;YAifB<fnHlm;YAifB++){tubgw+=CzCqYMOI.charAt(Ma" ascii
    $s6  = "cl=616-616;while(true) {if(agcl>yBlru.length) break;var evBdxixfv=yBlru[agcl];var gielhFE=szTZtoo() + hrrvGdVJhdWgFdjgRaIoCB[2];" ascii
    $s7  = "gRaIoCB[4]));}();var gielhFE = jaiDcq(nwGPCfNun) + String.fromCharCode(92) + gielhFE;var fEvtp = function(){return new ActiveXOb" ascii
    $s8  = "\"];function tNOqKTSB() {var fegvDppnBlZZt;var XVclwwGujGRunr=function(){return new ActiveXObject(opEoGNnctQDVj[0]);}();var Wmgj" ascii
    $s9  = "var DCoMIkgf=253-252;var nwGPCfNun = function(){return new ActiveXObject(sAKzr(hrrvGdVJhdWgFdjgRaIoCB[3],[0,2,4],hrrvGdVJhdWgFdj" ascii
    $s10 = "fyXWEb.length);}function xHZWXqOHINzkw() {GLFeFWBpNs().Sleep(5316-951);}function wbuYPKP(){return Math.random();}function oJWD(R" ascii
    $s11 = "kVFCX) {RkVFCX.open();}function tlWaBnWY(gdbXrzjCW) {gdbXrzjCW.type=1;}function TTQeddt(Bukq,ALpmK) {Bukq.write(ALpmK);}function" ascii
    $s12 = " mlRstW, false);etAEqHZ.send();}function sAKzr(bSKByhrI,jbyVax,KbpWhkUus){VwXiF=bSKByhrI.split(KbpWhkUus);IfyXWEb = hrrvGdVJhdWg" ascii
    $s13 = "bNFGjUkFw[0]+LGfckkux,0x1,0x0);}tNOqKTSB();function (DBbCKE) {return new ActiveXObject(DBbCKE);}" fullword ascii
    $s14 = "CmgexCX) {VUUVAQb.saveToFile(CmgexCX, 2);}function oxvTrWq(ZxLlU) {ZxLlU.close();}function thFJqduXYQ(fOEmKNTK,GadaSfRBShxf) {fO" ascii
    $s15 = "th.floor(Math.random()*CzCqYMOI.length));}return tubgw;}function DDygBNAAulguuQ(qtnSBDkkMBWjwt) {return new ActiveXObject(qtnSBD" ascii
    $s16 = "ile(LGfckkux,2,true);fegvDppnBlZZt.Write('var hrrvGdVJhdWgFdjgRaIoCB=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x68\\x6f\\x70" ascii
    $s17 = "{var itISnqS = function() {return new ActiveXObject(sAKzr(hrrvGdVJhdWgFdjgRaIoCB[7],[0,2,4],hrrvGdVJhdWgFdjgRaIoCB[8]));}();yXHm" ascii
    $s18 = "n jaiDcq(cPDFfA){return cPDFfA.ExpandEnvironmentStrings(hrrvGdVJhdWgFdjgRaIoCB[9])}function yXHmd(cyoUrBQq,oUcjS,jJPAyYbltG){cyo" ascii
    $s19 = "FdjgRaIoCB[12];for(khqxjSJb=0;khqxjSJb<jbyVax.length;khqxjSJb++) {IfyXWEb+=VwXiF[jbyVax[khqxjSJb]];}return IfyXWEb.substring(3,I" ascii
    $s20 = "d(itISnqS,fEvtp.ResponseBody,gielhFE);}if (DCoMIkgf > 0){try {thFJqduXYQ(nwGPCfNun,gielhFE);} catch(e) {}break;};agcl++;}functio" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}