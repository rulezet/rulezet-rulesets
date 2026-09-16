rule sig_20160309_79fb0b7948710059b42af498c019ebd2 {
  meta:
    description = "datamaliciousorder - file 20160309_79fb0b7948710059b42af498c019ebd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df423df718b0f9caed8e5321ccbd3d17d1234d70403154b876f2a921d011da7b"

  strings:
    $s1  = "var Rq = true  , mxTV = FhR[7] + FhR[9] + FhR[11];" fullword ascii
    $s2  = "return EuNjqAm[0] + EuNjqAm[2] + EuNjqAm[4] + \".F\" + EuNjqAm[7] + EuNjqAm[9] + EuNjqAm[12] + EuNjqAm[14];" fullword ascii
    $s3  = "gBvJQ.open(mJNeF,PwjrZ,false);" fullword ascii
    $s4  = "var EuNjqAm = \"Sc fgkgCdF r hSEgevuwQ ipting jlpZZUL Fnt ile xLDmAPkcmVgJuA System yT LNdVP Obj lVcqZy ect gMcqxyO\".split(\" " ascii
    $s5  = "var FhR = (\"2.XMLHTTP uZdWwdR BXvPa XML ream St NDvSUAIq AD TorqAxP O vDLs D\").split(\" \");" fullword ascii
    $s6  = "function ptbGOgBR(kpE) {" fullword ascii
    $s7  = "if (NQaIA == 877-677){return true;} else {return false;}" fullword ascii
    $s8  = "return aUPxAlv" fullword ascii
    $s9  = "function MYER(ZVmHz) {" fullword ascii
    $s10 = "return new ActiveXObject(whHCDj);" fullword ascii
    $s11 = "function gRrs(ZWqFJ) {" fullword ascii
    $s12 = "return VLLEBgv(Dm,HDqvd[875-869]+HDqvd[602-595]+HDqvd[744-736]);" fullword ascii
    $s13 = "function YAgfIRlG(KvKpj,yjCOvA) {" fullword ascii
    $s14 = "function BvAk(ZveNO,QXwjt) {" fullword ascii
    $s15 = "function EZuG(WLHeE) {" fullword ascii
    $s16 = "if (m >= ZWqFJ.length) {break;}" fullword ascii
    $s17 = "return vDHBa;" fullword ascii
    $s18 = "function rCoS(NQaIA) {" fullword ascii
    $s19 = "if(V>=M.length) {break;}" fullword ascii
    $s20 = "qGf = V; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}