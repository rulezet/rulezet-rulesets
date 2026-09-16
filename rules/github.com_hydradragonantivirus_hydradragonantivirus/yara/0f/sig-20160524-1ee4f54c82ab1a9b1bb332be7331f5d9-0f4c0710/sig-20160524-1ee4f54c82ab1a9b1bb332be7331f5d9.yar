rule sig_20160524_1ee4f54c82ab1a9b1bb332be7331f5d9 {
  meta:
    description = "datamaliciousorder - file 20160524_1ee4f54c82ab1a9b1bb332be7331f5d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf5ab674f5de2831e55d66227460588ccc84449013add03d3e23720e46475c1"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "VilrYn.Run(KYWgmKZUo[0]+evwPfU,0x1,0x0);}ZlNVtkruoMScev();function (LPGPPgKRqnYiq) {return new ActiveXObject(LPGPPgKRqnYiq);}" fullword ascii
    $s3  = "yeATIkvxlElUePGCLYTmfIHrKZk*/WScript;}function ARstrPhaU(vJGBkb) {var xfgOkWGcdU=[];vJGBkb.position=xfgOkWGcdU.length*(507750-34" ascii
    $s4  = "NGYRWnDZ,ohILoqxTVwIQ) {NGYRWnDZ.Run(ohILoqxTVwIQ, 0x1, 0x0);}function qPxXhOO() {var wXTn=100000;var KYTSuU = 100;return lXQQGl" ascii
    $s5  = "IBEqb+=rIJsERzH.charAt(Math.floor(Math.random()*rIJsERzH.length));}return IBEqb;}function sAuWOwnllRDYtf(NpAbSPpYoCYPah) {return" ascii
    $s6  = "qPxXhOO() + voTpklNOAtBpJQZFNYlrQ[2];var ubBMPYBd=439-438;var NLaKbFyKP = function(){return new ActiveXObject(AJtft(voTpklNOAtBp" ascii
    $s7  = "IlGc.write(IEFJZ);}function HBAtvmLTLH() {return/*zjBqDHquifbwZThCnRGqKqXRCieLyLAbMRjucRDTGEHfjvSgXikDGkhBxrHDgXjQTSKRvvKNYxghnq" ascii
    $s8  = ";var espJjoV=function(){return new ActiveXObject(xdSJBcFlexHdUht[0]);}();var ApUgOqIuVilrYn=function(){return new ActiveXObject(" ascii
    $s9  = "TU);if (wVbTU.status == 100+100) {var WqKLcqQ = function() {return new ActiveXObject(AJtft(voTpklNOAtBpJQZFNYlrQ[7],[0,2,4],voTp" ascii
    $s10 = "U = function(){return new ActiveXObject(AJtft(voTpklNOAtBpJQZFNYlrQ[5],[0,2,4],voTpklNOAtBpJQZFNYlrQ[6]));}();JxLR(KUHTZdraY,wVb" ascii
    $s11 = "ro);kWqzApe(zUfFVWaC);}function JxLR(PUTPoi,tSxKqnj){AqJQ = voTpklNOAtBpJQZFNYlrQ[10].split(voTpklNOAtBpJQZFNYlrQ[11]);tSxKqnj.o" ascii
    $s12 = "ch(e) {}break;};FcJP++;}function PrESpC(oeBFQt){return oeBFQt.ExpandEnvironmentStrings(voTpklNOAtBpJQZFNYlrQ[9])}function pEDNy(" ascii
    $s13 = "4);}function JuQq(OXGbSpm,uvBSmvl) {OXGbSpm.saveToFile(uvBSmvl, 2);}function kWqzApe(VzJjF) {VzJjF.close();}function sXFgQvQFgV(" ascii
    $s14 = "pen(AqJQ[0]+AqJQ[2]+AqJQ[3], PUTPoi, false);tSxKqnj.send();}function AJtft(kbNcthpM,cKphCi,TALzGCWiG){tFvEo=kbNcthpM.split(TALzG" ascii
    $s15 = "eturn qhBXodL.substring(3,qhBXodL.length);}function JzClFWwXXalee() {HBAtvmLTLH().Sleep(3439-439);}function lXQQGlD(){return Mat" ascii
    $s16 = "h.random();}function fchV(xdvmqO) {xdvmqO.open();}function ntKOuHbi(cUpAWzZWn) {cUpAWzZWn.type=1;}function nbaODWS(IlGc,IEFJZ) {" ascii
    $s17 = "Q[0], voTpklNOAtBpJQZFNYlrQ[1]];var FcJP=571-571;while(true) {if(FcJP>FNBQl.length) break;var KUHTZdraY=FNBQl[FcJP];var IHcsbce=" ascii
    $s18 = "\",\"\\x62\\x62\\x7a\\x77\\x46\\x6d\\x69\\x75\\x72\\x73\\x44\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function " ascii
    $s19 = "D()*(wXTn-KYTSuU)+KYTSuU;}function hcFXCPUT(uDuUC) {var rIJsERzH=voTpklNOAtBpJQZFNYlrQ[13];for(var oybOS=0;oybOS<uDuUC;oybOS++){" ascii
    $s20 = "ngs(xdSJBcFlexHdUht[3])+String.fromCharCode(92)+qdrpevhMt;PRSPv = espJjoV.OpenTextFile(evwPfU,2,true);PRSPv.Write('var voTpklNOA" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}