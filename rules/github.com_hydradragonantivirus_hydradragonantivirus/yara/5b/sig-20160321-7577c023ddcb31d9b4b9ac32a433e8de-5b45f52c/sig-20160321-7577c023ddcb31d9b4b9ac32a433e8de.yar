rule sig_20160321_7577c023ddcb31d9b4b9ac32a433e8de {
  meta:
    description = "datamaliciousorder - file 20160321_7577c023ddcb31d9b4b9ac32a433e8de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "370f0ca29350f5cae343639bb7bea2266ed24c7d44e4bcc60da976f8974aacdc"

  strings:
    $s1  = "return WScript.CreateObject(xDLwc);" fullword ascii
    $s2  = "return ZjTMAnT[0] + ZjTMAnT[2] + ZjTMAnT[4] + \".F\" + ZjTMAnT[7] + ZjTMAnT[9] + ZjTMAnT[12] + ZjTMAnT[14];" fullword ascii
    $s3  = "var Pe = true  , wiwS = VZZ[7] + VZZ[9] + VZZ[11];" fullword ascii
    $s4  = "var ZjTMAnT = khyFL(DSEarJLuII+\" \"+\"System wu jlsAi Obj TWNXWR ect BcTxApv QAavV\", \" \");" fullword ascii
    $s5  = "gWQub.open(PokFr,ZaxKu,false);" fullword ascii
    $s6  = "if (dHYWl == 539-339){return true;} else {return false;}" fullword ascii
    $s7  = "function GAvj(IHrBx) {" fullword ascii
    $s8  = "if (m >= IHrBx.length) {break;}" fullword ascii
    $s9  = "function khyFL(Uhp,bZIRZ) {" fullword ascii
    $s10 = "function ZInXHmi(yfLq,EWhRP) {" fullword ascii
    $s11 = "function xKApcCU(FcRa) {" fullword ascii
    $s12 = "function ETIO(fBtpe) {" fullword ascii
    $s13 = "return ZInXHmi(hN,NTKHv[681-675]+NTKHv[778-771]+NTKHv[669-661]);" fullword ascii
    $s14 = "return BLf.size;" fullword ascii
    $s15 = "function ufMzSMvmY(vmxHvSlWtUN) {" fullword ascii
    $s16 = "function rpUK(gWQub,ZaxKu,PokFr) {" fullword ascii
    $s17 = "function UKQZ(jhSBK,cEoRs) {" fullword ascii
    $s18 = "return Dagvpi.position=623-623;" fullword ascii
    $s19 = "function iGxr(cgPYD) {" fullword ascii
    $s20 = "function hOXV(dHYWl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}