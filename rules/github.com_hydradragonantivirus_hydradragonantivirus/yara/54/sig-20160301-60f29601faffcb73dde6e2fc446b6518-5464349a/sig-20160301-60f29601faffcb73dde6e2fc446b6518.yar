rule sig_20160301_60f29601faffcb73dde6e2fc446b6518 {
  meta:
    description = "datamaliciousorder - file 20160301_60f29601faffcb73dde6e2fc446b6518.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0cc36919c088c8b0cf14c15f4883006cfab246e24a9374a9ed6c4c065ed8995"

  strings:
    $s1  = "var aE = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(LmngI);" fullword ascii
    $s3  = "var NdE = (hUO + \"TTP\" + \" rzCmRPh svytB XML ream St WmNsyQMn AD Xogpwkr OD\").split(\" \");" fullword ascii
    $s4  = "var Pk = true  , cBdi = NdE[7] + \"\" + NdE[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + ONaSwpF + \".F\" + HBxsQOKIRV + lnXOO + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "kBTiQ.open(KHUOP,tObnU,false);" fullword ascii
    $s7  = "xmz = V; break; " fullword ascii
    $s8  = "if(V>=W.length) {break;}" fullword ascii
    $s9  = "return new ActiveXObject(oGvDPD);" fullword ascii
    $s10 = "if (((new Date())>0,7101010888)) {" fullword ascii
    $s11 = "if (CNOZy == 640-440){return true;} else {return false;}" fullword ascii
    $s12 = "return cMKDK.status;" fullword ascii
    $s13 = "function MAACm(oGvDPD) {" fullword ascii
    $s14 = "function EdhB(LmngI) {" fullword ascii
    $s15 = "function kozn(cMKDK) {" fullword ascii
    $s16 = "function sDpB(CNOZy) {" fullword ascii
    $s17 = "if (ATmyV > 193113-530){return true;} else {return false;}" fullword ascii
    $s18 = "function EarS(kBTiQ,tObnU,KHUOP) {" fullword ascii
    $s19 = "function VtHv(tZWjN) {" fullword ascii
    $s20 = "return UWFku;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}