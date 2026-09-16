rule sig_20160429_042ada21759825a0d3cee99c15fe0817 {
  meta:
    description = "datamaliciousorder - file 20160429_042ada21759825a0d3cee99c15fe0817.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e6f26995c6cd0816ec93088e45d18a6f1e1ea3e30feacc818b5a9368cef39ff"

  strings:
    $s1 = "SPEC';var s4='\"&i';z29+='% /c';var c67='U L';z29+=' REG';var o53='; ';z29+=' A';var v87='0.ex';z29+='DD \"';var x76='\"\")';z29" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}