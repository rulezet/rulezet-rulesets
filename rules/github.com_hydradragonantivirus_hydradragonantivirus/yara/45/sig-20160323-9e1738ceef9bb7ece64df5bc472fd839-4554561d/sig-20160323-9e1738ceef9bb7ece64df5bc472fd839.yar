rule sig_20160323_9e1738ceef9bb7ece64df5bc472fd839 {
  meta:
    description = "datamaliciousorder - file 20160323_9e1738ceef9bb7ece64df5bc472fd839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f8165277811437ae5f6df57ba09aa287871a5b15b35cdff772e2d2a621ad663"

  strings:
    $s1  = "return WScript.CreateObject(eHFuQ);" fullword ascii
    $s2  = "return nLNWujq[0] + nLNWujq[2] + nLNWujq[4] + \".F\" + nLNWujq[7] + nLNWujq[9] + nLNWujq[12] + nLNWujq[14];" fullword ascii
    $s3  = "var cU = true  , RWnY = BST[7] + BST[9] + BST[11];" fullword ascii
    $s4  = "var BST = (\"2.XMLHTTP yvCFzNw KiiPi XML ream St sgBBuuCb AD WkjkAbY O VAGL D\").split(\" \");" fullword ascii
    $s5  = "var nLNWujq = iTUpD(VgJkuvRXnd+\" \"+\"System OC Ooakb Obj yENAFh ect KeVwkwj ldCPr\", \" \");" fullword ascii
    $s6  = "jrBf.open(Kstfh,hQrNn,false);" fullword ascii
    $s7  = "return XDnvuj/*DrLkyWMlzaUnJiOgMlG4Cc0wx*/.position=361-361;" fullword ascii
    $s8  = "return AER.split(AezMw);" fullword ascii
    $s9  = "return GQfRGFj(RR,Nlpuo[294-288]+Nlpuo[795-788]+Nlpuo[117-109]);" fullword ascii
    $s10 = "function MTDS(mzRyW) {" fullword ascii
    $s11 = "function EXyR(AhJUF) {" fullword ascii
    $s12 = "function hyqr(eHFuQ) {" fullword ascii
    $s13 = "function gUwg(eLWlm,hQrNn,Kstfh) {" fullword ascii
    $s14 = "return xkrxY;" fullword ascii
    $s15 = "function FCLt(BybHR,dchNH) {" fullword ascii
    $s16 = "function cPrgM(XDnvuj) {" fullword ascii
    $s17 = "function GQfRGFj(VPUS,uBZvp) {" fullword ascii
    $s18 = "if (AhJUF == 369-169){return true;} else {return false;}" fullword ascii
    $s19 = "function LMLISBpy(Idgk) {" fullword ascii
    $s20 = "function riBm(BCFPx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}