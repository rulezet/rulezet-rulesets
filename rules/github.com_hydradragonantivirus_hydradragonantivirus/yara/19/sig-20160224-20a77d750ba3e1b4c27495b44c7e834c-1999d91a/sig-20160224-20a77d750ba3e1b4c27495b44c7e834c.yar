rule sig_20160224_20a77d750ba3e1b4c27495b44c7e834c {
  meta:
    description = "datamaliciousorder - file 20160224_20a77d750ba3e1b4c27495b44c7e834c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b5cf666412824375d6ba556204c9628acc3dff1a52ae85bbbaf8f50cf1bf645"

  strings:
    $s1 = "    var vassalErS = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[endemicpHM](warrantq5k);" fullword ascii
    $s3 = "var appeaseHRz = function(laggardXNR) {" fullword ascii
    $s4 = "var codicili6P = function() {" fullword ascii
    $s5 = "function btoa(suffrageCJX, caballs9, subalternrod) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}