rule sig_20160530_8d91342561572f716aefa55dfe43fe79 {
  meta:
    description = "datamaliciousorder - file 20160530_8d91342561572f716aefa55dfe43fe79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79fcfcded8b8f6f099eadf6a69dfe96087d7d1a60a7e9669dafba55d23c0dfcf"

  strings:
    $s1  = "var gnieFjOn=function(){return WScript.CreateObject(glDDdqUDuRuWPUtp[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function EErmNZczBn(BVhcYRHuHZFUqOMICqieWLD,xxiCWDNomiI){return BVhcYRHuHZFUqOMICqieWLD.charAt(xxiCWDNomiI);}" fullword ascii
    $s3  = "function dWbvuLEMz(zsdsAhAdjmRLJ,yoeTR,LskrzBYDyr){WoKahtMbWb=zsdsAhAdjmRLJ.split(LskrzBYDyr);tttqJ = glDDdqUDuRuWPUtp[0];for(SC" ascii
    $s4  = "function rupQRVZzWIQqD(BSbraHQ,GCEoTv,lPQyuuGZlazzGtfQNYrcUEL){return String.fromCharCode(BSbraHQ,GCEoTv,lPQyuuGZlazzGtfQNYrcUEL" ascii
    $s5  = "function dWbvuLEMz(zsdsAhAdjmRLJ,yoeTR,LskrzBYDyr){WoKahtMbWb=zsdsAhAdjmRLJ.split(LskrzBYDyr);tttqJ = glDDdqUDuRuWPUtp[0];for(SC" ascii
    $s6  = "var aIdxTF=function(){return new ActiveXObject(glDDdqUDuRuWPUtp[1]);}();" fullword ascii
    $s7  = "twqLJun=0;SCtwqLJun<yoeTR.length;SCtwqLJun++) {tttqJ+=WoKahtMbWb[yoeTR[SCtwqLJun]];}return tttqJ.substring(3,tttqJ.length);}" fullword ascii
    $s8  = "var fIKxkJt = aIdxTF.createtextfile(gnieFjOn.ExpandEnvironmentStrings(glDDdqUDuRuWPUtp[3]+glDDdqUDuRuWPUtp[4])+String.fromCharCo" ascii
    $s9  = "push(\"D\");spAigIqENmmllJPEDS.push(\"3\");spAigIqENmmllJPEDS.push(\"E\");spAigIqENmmllJPEDS.push(\"F\");spAigIqENmmllJPEDS.push" ascii
    $s10 = "function kVkvbKJZAaXp(){return dWbvuLEMz(glDDdqUDuRuWPUtp[9],[1,5,7],glDDdqUDuRuWPUtp[10]);}" fullword ascii
    $s11 = "function KYzxdW(ZlBGlLkTVCvOX,eVGOnBs) {var pYCCfNiLRKX=[glDDdqUDuRuWPUtp[15]];ZlBGlLkTVCvOX[pYCCfNiLRKX[0]]" fullword ascii
    $s12 = "function ZlYWyJaMx(){return dWbvuLEMz(glDDdqUDuRuWPUtp[13],[0,3,6],glDDdqUDuRuWPUtp[14]);}" fullword ascii
    $s13 = "hYffO = usDBmADKgAj & 0xff;if (VKzcjuxoyqbwxNHHMvp == 64) UAkXxB += MC(PluYvEdDQB);else if (bHKUpWnbhFgszIy == 64) UAkXxB += hdf" ascii
    $s14 = "fNvbggVrpGAT(PluYvEdDQB, aHVKtgdnNXSbMLaWlw);else UAkXxB += rupQRVZzWIQqD(PluYvEdDQB, aHVKtgdnNXSbMLaWlw, vfhYffO);} while (HaIt" ascii
    $s15 = "function Bfgmxcw(){return gnieFjOn.ExpandEnvironmentStrings(kVkvbKJZAaXp())}" fullword ascii
    $s16 = "aHikTfBRifvZyFhAyBz < aFqTHmxgzihaW.length);return UAkXxB;}" fullword ascii
    $s17 = "function rupQRVZzWIQqD(BSbraHQ,GCEoTv,lPQyuuGZlazzGtfQNYrcUEL){return String.fromCharCode(BSbraHQ,GCEoTv,lPQyuuGZlazzGtfQNYrcUEL" ascii
    $s18 = "function hdffNvbggVrpGAT(vzHeHJWtqlRXs,RvMIVMiLpYDFvV){return String.fromCharCode(vzHeHJWtqlRXs,RvMIVMiLpYDFvV);}" fullword ascii
    $s19 = "function MC(sRZfELbJuZAQVs){return String.fromCharCode(sRZfELbJuZAQVs);}" fullword ascii
    $s20 = "de(92)+glDDdqUDuRuWPUtp[5],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}