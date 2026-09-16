rule sig_20160224_a201afb1dda2c6731bcc8730b949f851 {
  meta:
    description = "datamaliciousorder - file 20160224_a201afb1dda2c6731bcc8730b949f851.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eefe732f16cc2639acc6848fdc1e34936c5fbb8e1746828b26b178d75385a5d"

  strings:
    $s1 = "        return WScript[derelictlNL](cleaveIUL);" fullword ascii
    $s2 = "var raptpdL = function(financialp7u) {" fullword ascii
    $s3 = "    var laggardcAa = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s4 = "var expatiateP3y = function() {" fullword ascii
    $s5 = "function btoa(burnishSgu, felicitousCj4, perpetualfK1, unctionJr7, vexwoO, convalesceeAH, inflammatoryaT9, incandescentFkB, succ" ascii
    $s6 = "function btoa(burnishSgu, felicitousCj4, perpetualfK1, unctionJr7, vexwoO, convalesceeAH, inflammatoryaT9, incandescentFkB, succ" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}