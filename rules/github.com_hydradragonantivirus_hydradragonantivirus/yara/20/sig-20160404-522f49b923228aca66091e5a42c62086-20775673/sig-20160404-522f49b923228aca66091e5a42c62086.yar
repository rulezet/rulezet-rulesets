rule sig_20160404_522f49b923228aca66091e5a42c62086 {
  meta:
    description = "datamaliciousorder - file 20160404_522f49b923228aca66091e5a42c62086.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa0a8750723cdf0312068beb9b5d1e1e02d741f773e7abc97e2d91d7d45b128a"

  strings:
    $s1  = "return XgFykMv[0] + XgFykMv[2] + XgFykMv[4] + \".F\" + XgFykMv[7] + XgFykMv[9] + XgFykMv[12] + XgFykMv[14];" fullword ascii
    $s2  = "var CH = true  , Qwlj = jMr[7] + jMr[9] + jMr[11];" fullword ascii
    $s3  = "var jMr = (\"2.XMLHTTP ghLoKTp Qyzit XML ream St rwciJYHe AD yMLxCnf O aqTB D\").split(\" \");" fullword ascii
    $s4  = "SAAW.open(oZZxA,NGEFT,false);" fullword ascii
    $s5  = "var XgFykMv = eVjVb(GIMQLapbqs+\" \"+\"System SE jpkmF Obj ypNzTM ect kEWqBJY YIbyz\", \" \");" fullword ascii
    $s6  = "function qkxrzEZ(oFQf) {" fullword ascii
    $s7  = "function zaju(kZEMB) {" fullword ascii
    $s8  = "return oXKyFPl;" fullword ascii
    $s9  = "function EfifGyUC(JfGx) {" fullword ascii
    $s10 = "function eVjVb(wBn,NDtor) {" fullword ascii
    $s11 = "if (g >= LVbHA.length) {break;}" fullword ascii
    $s12 = "function FfWu(Ojpel) {" fullword ascii
    $s13 = "function RCCzrx(DdgM,zUfQdk) {" fullword ascii
    $s14 = "function jysV(THaCy) {" fullword ascii
    $s15 = "return wjPrrCK;" fullword ascii
    $s16 = "function Itrm(vMXRE,NGEFT,oZZxA) {" fullword ascii
    $s17 = "function yMHk(IFtgD,cVePD) {" fullword ascii
    $s18 = "function kgUg(FMWXp,tFCbB) {" fullword ascii
    $s19 = "function tqir(FmwRq) {" fullword ascii
    $s20 = "function bgqc(ZTcOu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}