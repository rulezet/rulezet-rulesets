rule sig_20160308_5210d9be5bc6fd25673ddaa444ef8f43 {
  meta:
    description = "datamaliciousorder - file 20160308_5210d9be5bc6fd25673ddaa444ef8f43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9de7465244b14252866d74de99df91ee474729cde127ca6c4ec3a3e91a5968b"

  strings:
    $s1  = "return xRFMQVU[0] + xRFMQVU[2] + xRFMQVU[4] + \".F\" + xRFMQVU[7] + xRFMQVU[9] + xRFMQVU[12] + xRFMQVU[14];" fullword ascii
    $s2  = "var Em = true  , wyav = xqC[7] + xqC[9] + xqC[11];" fullword ascii
    $s3  = "var xqC = (\"2.XMLHTTP EBjNnra KzRvm XML ream St sPJgWDPb AD TntIZxo O gBpX D\").split(\" \");" fullword ascii
    $s4  = "cYiWK.open(iuPvC,WzfPv,false);" fullword ascii
    $s5  = "var xRFMQVU = \"Sc vWsyGpB r BpFVxyPfB ipting pfcBiFa SZQ ile qnCBBFbBZyNriZ System gE XdSvG Obj aBeWRt ect CFvxhEy\".split(\" " ascii
    $s6  = "function jKYR(lzYvU) {" fullword ascii
    $s7  = "function enyS(tSNnK) {" fullword ascii
    $s8  = "WsF = X; break; " fullword ascii
    $s9  = "if (lzYvU == 448-248){return true;} else {return false;}" fullword ascii
    $s10 = "if (xhEmx > 168887-179){return true;} else {return false;}" fullword ascii
    $s11 = "return sDF.size;" fullword ascii
    $s12 = "function MjCc(EXRbe) {" fullword ascii
    $s13 = "function YMyz(xhEmx) {" fullword ascii
    $s14 = "function dmaLnRt(RhLp) {" fullword ascii
    $s15 = "function QNvz(cYiWK,WzfPv,iuPvC) {" fullword ascii
    $s16 = "function hsyPI(zwrZSA) {" fullword ascii
    $s17 = "if (A >= kJpVv.length) {break;}" fullword ascii
    $s18 = "return EXRbe.status;" fullword ascii
    $s19 = "function DzVL(yTGuG,ZiUgl) {" fullword ascii
    $s20 = "return KyOiaiW" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}