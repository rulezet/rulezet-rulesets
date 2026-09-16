rule sig_20160527_1c6f720b6b27bcb75e7538bbd56f1315 {
  meta:
    description = "datamaliciousorder - file 20160527_1c6f720b6b27bcb75e7538bbd56f1315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e85fcf0c55d13d5b091d875c5ba20a3b71969883bea45dc1c51504f8089ddf3"

  strings:
    $s1  = "function gyWKwXuzq() {return WScript;}function qmLMRMuShjILx(){return awMmfZ.ExpandEnvironmentStrings(wJMSBLAlbmqQ())}" fullword ascii
    $s2  = "function SFOIbVDezOBYTwfIYJxtD(LbKWURUjvtfncAcMO,JKuwsFHulVaaxj){return LbKWURUjvtfncAcMO.charAt(JKuwsFHulVaaxj);}" fullword ascii
    $s3  = "var fljiaUGTA = chBKghwqeoAHRJ.createtextfile(awMmfZ.ExpandEnvironmentStrings(TKBNMIARq[2]+TKBNMIARq[3])+String.fromCharCode(92)" ascii
    $s4  = "function Fs(TNhdVWPOfXDUDgqRFllVBhl){return String.fromCharCode(TNhdVWPOfXDUDgqRFllVBhl);}" fullword ascii
    $s5  = "function bvGtz(bouVbyjqCOQYf) {var iMnKcrgZbuLERQiWmn = IWdlAYhuQzesfexH.join(TKBNMIARq[6]);var URAQL, favTOokwODLWdMgcPEMDHgkW," ascii
    $s6  = "function dgqIqwShUfDmOojP(KiyCDGkAklSwNxXgOoxjEtlQ,BKsiZOgjcLvGO,xTzPmYoJxjcHpNiphOL){return String.fromCharCode(KiyCDGkAklSwNxX" ascii
    $s7  = "var awMmfZ=function(){return gyWKwXuzq().CreateObject(TKBNMIARq[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "+TKBNMIARq[4],true);" fullword ascii
    $s9  = "function kYLDZOujwuNW(HwaSBkkZxIZPjO,TAtpCOn) {var jDcwp=[TKBNMIARq[15]];HwaSBkkZxIZPjO[jDcwp[0]](TAtpCOn,0x1,0x0)}" fullword ascii
    $s10 = "function MIDYTUewNMaegGdkzJZE(zjZMyOWf,xVEVtwpmREpSUll){return String.fromCharCode(zjZMyOWf,xVEVtwpmREpSUll);}" fullword ascii
    $s11 = "function dgqIqwShUfDmOojP(KiyCDGkAklSwNxXgOoxjEtlQ,BKsiZOgjcLvGO,xTzPmYoJxjcHpNiphOL){return String.fromCharCode(KiyCDGkAklSwNxX" ascii
    $s12 = "function ZAVgGKMEgnlth(){return FViLrZxDqq(TKBNMIARq[10],[2,4,8,10],TKBNMIARq[11]);}" fullword ascii
    $s13 = "function FViLrZxDqq(ZCmTebcjWav,qKHqLoAUmgTO,eZnqbQgck){yQDtQAOZiLEjby=ZCmTebcjWav.split(eZnqbQgck);DHABTmiL = TKBNMIARq[14];for" ascii
    $s14 = "M);} while (FQxtzAXloRFIoOYYX < bouVbyjqCOQYf.length);return YssmBWlNjqENAmxBQmw;}" fullword ascii
    $s15 = "var chBKghwqeoAHRJ=function(){return new ActiveXObject(TKBNMIARq[0]);}();" fullword ascii
    $s16 = "function bvGtz(bouVbyjqCOQYf) {var iMnKcrgZbuLERQiWmn = IWdlAYhuQzesfexH.join(TKBNMIARq[6]);var URAQL, favTOokwODLWdMgcPEMDHgkW," ascii
    $s17 = "tnWlTHcODpS == 64) YssmBWlNjqENAmxBQmw += Fs(URAQL);else if (nEgdZnDBCBzjefZYxSp == 64) YssmBWlNjqENAmxBQmw += MIDYTUewNMaegGdkz" ascii
    $s18 = "function wJMSBLAlbmqQ(){return FViLrZxDqq(TKBNMIARq[8],[1,5,7],TKBNMIARq[9]);}" fullword ascii
    $s19 = "function cRcXRpeovMk(){return FViLrZxDqq(TKBNMIARq[12],[0,3,6],TKBNMIARq[13]);}" fullword ascii
    $s20 = "function FViLrZxDqq(ZCmTebcjWav,qKHqLoAUmgTO,eZnqbQgck){yQDtQAOZiLEjby=ZCmTebcjWav.split(eZnqbQgck);DHABTmiL = TKBNMIARq[14];for" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}