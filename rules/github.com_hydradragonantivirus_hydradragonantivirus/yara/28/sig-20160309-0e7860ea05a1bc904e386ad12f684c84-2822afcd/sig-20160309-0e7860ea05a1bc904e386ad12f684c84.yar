rule sig_20160309_0e7860ea05a1bc904e386ad12f684c84 {
  meta:
    description = "datamaliciousorder - file 20160309_0e7860ea05a1bc904e386ad12f684c84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7801247c5e08a84fb084d3269c493505042ac6751d978f8e77048bec6b615c5c"

  strings:
    $s1  = "return DeekDYQ[0] + DeekDYQ[2] + DeekDYQ[4] + \".F\" + DeekDYQ[7] + DeekDYQ[9] + DeekDYQ[12] + DeekDYQ[14];" fullword ascii
    $s2  = "var jd = true  , aTAw = XBs[7] + XBs[9] + XBs[11];" fullword ascii
    $s3  = "PDqbm.open(tsbLg,uocUW,false);" fullword ascii
    $s4  = "var DeekDYQ = \"Sc UBauAnk r MPljVloDw ipting DzyHomF JFz ile PQZpMBPrnLIlJN System Wi bglAg Obj XEpOTy ect GWFMEQF\".split(\" " ascii
    $s5  = "var XBs = (\"2.XMLHTTP eBYuYUh TdABM XML ream St KmdTwGir AD MLYFbcR O kAtS D\").split(\" \");" fullword ascii
    $s6  = "function XYQnDBrj(jdg) {" fullword ascii
    $s7  = "if(p>=x.length) {break;}" fullword ascii
    $s8  = "function tfUolNwUu(LgKwf,jbPyv,tRLOk,BvJR) {" fullword ascii
    $s9  = "return jdg.size;" fullword ascii
    $s10 = "function KMPL(nDNNL,FjuBy) {" fullword ascii
    $s11 = "function owLV(jxZdm) {" fullword ascii
    $s12 = "if (B >= XjjnN.length) {break;}" fullword ascii
    $s13 = "function MzVt(dFgGX) {" fullword ascii
    $s14 = "wxi = p; break; " fullword ascii
    $s15 = "return new ActiveXObject(NSuqgX);" fullword ascii
    $s16 = "function sjhI(XNiFu) {" fullword ascii
    $s17 = "return yhpZUrG(ej,VvhOx[824-818]+VvhOx[607-600]+VvhOx[506-498]);" fullword ascii
    $s18 = "return QwHh.responseBody;" fullword ascii
    $s19 = "function wRnOhKxfp(tzOFFJeOjKa) {" fullword ascii
    $s20 = "function kwwYKgs(QwHh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}