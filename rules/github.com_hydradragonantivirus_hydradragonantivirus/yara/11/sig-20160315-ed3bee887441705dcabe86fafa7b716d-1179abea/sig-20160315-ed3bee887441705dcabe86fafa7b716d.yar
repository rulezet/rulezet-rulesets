rule sig_20160315_ed3bee887441705dcabe86fafa7b716d {
  meta:
    description = "datamaliciousorder - file 20160315_ed3bee887441705dcabe86fafa7b716d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d64b786d3e0592536c5e25da96cf5440766baaf0857dd0d33d42a716a90c289"

  strings:
    $s1  = "var AE = true  , rRRt = sqs[7] + sqs[9] + sqs[11];" fullword ascii
    $s2  = "return GpKsajH[0] + GpKsajH[2] + GpKsajH[4] + \".F\" + GpKsajH[7] + GpKsajH[9] + GpKsajH[12] + GpKsajH[14];" fullword ascii
    $s3  = "HLMEW.open(EJIYF,dqMUJ,false);" fullword ascii
    $s4  = "var GpKsajH = MztHQ(\"Sc rhfWjRq r wBVjlOMmu ipting kSAGhqY GGZ ile HyYZyGjAPUUgXM System QH kzhXf Obj BbFioN ect JYivPLM LFred" ascii
    $s5  = "var GpKsajH = MztHQ(\"Sc rhfWjRq r wBVjlOMmu ipting kSAGhqY GGZ ile HyYZyGjAPUUgXM System QH kzhXf Obj BbFioN ect JYivPLM LFred" ascii
    $s6  = "var sqs = (\"2.XMLHTTP TfluZAy qmDtz XML ream St mqTSxbGl AD ClVQYgM O eLHH D\").split(\" \");" fullword ascii
    $s7  = "return DaB.split(xQYjh);" fullword ascii
    $s8  = "function WuGL(EHNqm) {" fullword ascii
    $s9  = "function HfEV(WmOAJ,yFBGc) {" fullword ascii
    $s10 = "function LNogUOS(fvbK,zjQzk) {" fullword ascii
    $s11 = "function wpNp(iINBU) {" fullword ascii
    $s12 = "return QJAqKFI" fullword ascii
    $s13 = "function ATXj(HLMEW,dqMUJ,EJIYF) {" fullword ascii
    $s14 = "function bzMnCIogp(XqxcJSukqrU) {" fullword ascii
    $s15 = "return dVge.responseBody;" fullword ascii
    $s16 = "function kCLPy(buFCpQ) {" fullword ascii
    $s17 = "function ankx(IYavc) {" fullword ascii
    $s18 = "return LNogUOS(BH,Erguc[528-522]+Erguc[929-922]+Erguc[747-739]);" fullword ascii
    $s19 = "if (J >= suuYl.length) {break;}" fullword ascii
    $s20 = "function TANu(suyui) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}