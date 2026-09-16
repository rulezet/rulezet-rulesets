rule sig_20160224_82969e17cf667361ae4e64dffe0ff46f {
  meta:
    description = "datamaliciousorder - file 20160224_82969e17cf667361ae4e64dffe0ff46f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ea3529985bba9f6520a94786aa8a67388ceaeb8077083d51e074d17c732f04f"

  strings:
    $s1  = "function btoa(rarefiedaTE, sateRjC, pedanticNoM, recoursexHO, passeDJd, charyJKd, tourdUf, effeteTtc) {" fullword ascii
    $s2  = "    var tempervpT = function() {" fullword ascii
    $s3  = "    return tempervpT;" fullword ascii
    $s4  = "var prattletBc = function(afflicty8v) {" fullword ascii
    $s5  = "var prattleUN8 = function() {" fullword ascii
    $s6  = "    var syllogismIjK = false;" fullword ascii
    $s7  = "                        syllogismIjK = true;" fullword ascii
    $s8  = "    var carrionc3e = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s9  = "    tempervpT.prototype.V9BcbHa4hC = function(prognosticateuJK) {" fullword ascii
    $s10 = "    tempervpT.prototype.izUr51NDar = function(prognosticateuJK) {" fullword ascii
    $s11 = "        return WScript[gentilityPOu](prognosticateuJK);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}