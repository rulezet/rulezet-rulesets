rule sig_20160309_7a7157989b4c997e199e7ab5d693d3d1 {
  meta:
    description = "datamaliciousorder - file 20160309_7a7157989b4c997e199e7ab5d693d3d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fe63166d049241e8f0c5ccdeac322fbddc6639f84fe395d16968188ff52b78"

  strings:
    $s1  = "return lpXgqLP[0] + lpXgqLP[2] + lpXgqLP[4] + \".F\" + lpXgqLP[7] + lpXgqLP[9] + lpXgqLP[12] + lpXgqLP[14];" fullword ascii
    $s2  = "var wf = true  , WDbR = mzx[7] + mzx[9] + mzx[11];" fullword ascii
    $s3  = "var lpXgqLP = \"Sc AqBSNxw r YLBSmKcnZ ipting gncWvoX mQg ile AajdDgltQAtECu System Dw qSrOe Obj lgvmxO ect feoOWzj\".split(\" " ascii
    $s4  = "var mzx = (\"2.XMLHTTP FGeUcQJ zTHag XML ream St QQxMGjQl AD XboWPNw O AxAQ D\").split(\" \");" fullword ascii
    $s5  = "eebOa.open(zrXxf,GWUcb,false);" fullword ascii
    $s6  = "if(M>=S.length) {break;}" fullword ascii
    $s7  = "function KknfShLc(xfVwH,MSTfVJ) {" fullword ascii
    $s8  = "function AcKE(NWqZC) {" fullword ascii
    $s9  = "function oAXFXLtGn(WIdeQ,sQJBF,nXKfY,BIDd) {" fullword ascii
    $s10 = "return Tjz.size;" fullword ascii
    $s11 = "function hURI(YjaUv) {" fullword ascii
    $s12 = "return sGNoq;" fullword ascii
    $s13 = "return new ActiveXObject(tAmGlp);" fullword ascii
    $s14 = "function eLHP(SyLeh,yxMiI) {" fullword ascii
    $s15 = "fhm = M; break; " fullword ascii
    $s16 = "function RWLjvajQ(Tjz) {" fullword ascii
    $s17 = "function JUuz(eebOa,GWUcb,zrXxf) {" fullword ascii
    $s18 = "function AQGu(SSebK,mpIDK) {" fullword ascii
    $s19 = "function WfSn(oIwgz) {" fullword ascii
    $s20 = "return CXwW.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}