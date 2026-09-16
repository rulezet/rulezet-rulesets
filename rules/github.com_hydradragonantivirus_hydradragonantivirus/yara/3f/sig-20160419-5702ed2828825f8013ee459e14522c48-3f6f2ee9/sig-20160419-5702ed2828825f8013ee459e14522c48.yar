rule sig_20160419_5702ed2828825f8013ee459e14522c48 {
  meta:
    description = "datamaliciousorder - file 20160419_5702ed2828825f8013ee459e14522c48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4dd1ec756cae6e03ae7c17c1f0ee342dfaec97c124d88790d2245561b1bb823"

  strings:
    $s1  = "return WqJpdpt[0] + WqJpdpt[2] + WqJpdpt[4] + \".F\" + WqJpdpt[7] + WqJpdpt[9] + WqJpdpt[12] + WqJpdpt[14];" fullword ascii
    $s2  = "var rR = true  , XSBt = zYG[7] + zYG[9] + zYG[11];" fullword ascii
    $s3  = "var zYG = (\"2.XMLHTTP jCKdslH nmOxQ XML ream St fdviwWwJ AD pYZsHZa O jnbP D\").split(\" \");" fullword ascii
    $s4  = "yabR.open(uZLZm,MTrYH,false);" fullword ascii
    $s5  = "function IZRGpDhYf(uulngMquanX) {" fullword ascii
    $s6  = "function GlLs(qnfKQ,tByXw) {" fullword ascii
    $s7  = "function kalwypR(bIcf) {" fullword ascii
    $s8  = "return ODDagVI[0];" fullword ascii
    $s9  = "return bIcf[VfIBZNy[0]+VfIBZNy[1]];" fullword ascii
    $s10 = "if (ukfkC > 190002-688){return true;} else {return false;}" fullword ascii
    $s11 = "function ejdi(sZcLC,MTrYH,uZLZm) {" fullword ascii
    $s12 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s13 = "function FaUMAp(xRkNVRI) {" fullword ascii
    $s14 = "function HbSn(ukfkC) {" fullword ascii
    $s15 = "if(s>=J.length) {break;}" fullword ascii
    $s16 = "function cDeM(jVeBI) {" fullword ascii
    $s17 = "function cqFGVxcp(ZYL) {" fullword ascii
    $s18 = "return new ActiveXObject(BAgK);" fullword ascii
    $s19 = "function uoyhH(IzxywG) {" fullword ascii
    $s20 = "function gAvVY(RnO,WKhKL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}