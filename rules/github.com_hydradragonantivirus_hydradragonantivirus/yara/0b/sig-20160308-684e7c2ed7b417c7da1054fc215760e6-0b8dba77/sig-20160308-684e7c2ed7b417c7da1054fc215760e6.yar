rule sig_20160308_684e7c2ed7b417c7da1054fc215760e6 {
  meta:
    description = "datamaliciousorder - file 20160308_684e7c2ed7b417c7da1054fc215760e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "538b14c71e08bb1d52b42f21b5f01a8b6b75cac5ce57659c11ab603c1e92e30b"

  strings:
    $s1  = "return mFpRPyj[0] + mFpRPyj[2] + mFpRPyj[4] + \".F\" + mFpRPyj[7] + mFpRPyj[9] + mFpRPyj[12] + mFpRPyj[14];" fullword ascii
    $s2  = "var de = true  , qxJd = YlY[7] + YlY[9] + YlY[11];" fullword ascii
    $s3  = "var mFpRPyj = \"Sc HqtajxB r qElvILJwF ipting iPUhEhb sVP ile oexTgpejVPPEhz System HI BuiXn Obj OKOZLy ect AKfSGiU\".split(\" " ascii
    $s4  = "JpOKG.open(QsCYT,TlhkS,false);" fullword ascii
    $s5  = "function qnjtDqQCD(LIOLs,FDDgv,ibJNP,DSVs) {" fullword ascii
    $s6  = "function tkmo(OBKYn,sUthf) {" fullword ascii
    $s7  = "function wxbh(sbDuU) {" fullword ascii
    $s8  = "return new ActiveXObject(UisUXt);" fullword ascii
    $s9  = "if (O >= hJHLc.length) {break;}" fullword ascii
    $s10 = "return qasoBGH" fullword ascii
    $s11 = "if (rjZtS > 151155-918){return true;} else {return false;}" fullword ascii
    $s12 = "function RDxcCIIC() {" fullword ascii
    $s13 = "function cCfMSaWF(Yur) {" fullword ascii
    $s14 = "return uJlWC.status;" fullword ascii
    $s15 = "function DZGl(xyDEL) {" fullword ascii
    $s16 = "return mepYB;" fullword ascii
    $s17 = "function YdDMAhqrY(oaFUmcjsKHH) {" fullword ascii
    $s18 = "function KQKeU(UisUXt) {" fullword ascii
    $s19 = "function jmdN(XxHbo,FIjNB) {" fullword ascii
    $s20 = "pJA = R; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}