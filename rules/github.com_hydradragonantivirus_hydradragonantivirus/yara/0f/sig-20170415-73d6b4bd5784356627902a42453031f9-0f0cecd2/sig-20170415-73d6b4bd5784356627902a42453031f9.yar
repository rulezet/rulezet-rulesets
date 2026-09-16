rule sig_20170415_73d6b4bd5784356627902a42453031f9 {
  meta:
    description = "datamaliciousorder - file 20170415_73d6b4bd5784356627902a42453031f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af7365d57001b5e3f9fc96c7b9656b9f2a3d529df47e7c3e0fe69d52276cb653"

  strings:
    $x1  = "                shot[[\"run\"][0]]([al(0, \"e033\", [\"cmd.exe /\"]) + ante(0, \"Data\", [\"c \\\"powershell  $e\"]) + jpeg(0, " ascii
    $s2  = ", \"isOn\", [\"et-Exec'\"]) + able(0, \"Slug\", [\";$Text\"]) + mod(0, \"weak\", [\"='^ Process; \"]) + Keys(0, \"ev\", [\"$pat'" ascii
    $s3  = "                shot[[\"run\"][0]]([al(0, \"e033\", [\"cmd.exe /\"]) + ante(0, \"Data\", [\"c \\\"powershell  $e\"]) + jpeg(0, " ascii
    $s4  = "[\"+$raw\"]) + TO(0, \"rels\", [\"+$Gray+$ru)\"]) + tiny(0, \"mget\", [\";\\\\\"]) + deal(0, \"keys\", [\"\\\"\"])][0], plus);" fullword ascii
    $s5  = "='^ \"]) + abs(0, \"ff\", [\"Bypass \"]) + keep(0, \"tip\", [\"-Sc';$\"]) + DDD(0, \"f179\", [\"e006='^//ch';$\"]) + e010(0, \"S" ascii
    $s6  = "// movements had failed and were incompetent, that a na- " fullword ascii
    $s7  = "function ftps(Oral, Zero, host) {" fullword ascii
    $s8  = "\"]) + togx(0, \"cdup\", [\"';$RSD\"]) + LIST(0, \"syst\", [\"='^r';$Drop='^?f=3\"]) + Vine(0, \"opml\", [\".gif'',$path); ';\"]" ascii
    $s9  = "A1='\"]) + _(0, \"Any\", [\"^ome\"]) + FULL(0, \"nojq\", [\"skolz.';\"]) + Post(0, \"f227\", [\"$AF24='\"]) + Deck(0, \"ID3\", [" ascii
    $s10 = "Lord+$john+$\"]) + err(0, \"Matt\", [\"e00\"]) + ON(0, \"e137\", [\"6+$RSD+\"]) + noop(0, \"XHR\", [\"$A1+$m+$xbf+$Drop\"]) + It" ascii
    $s11 = "} /* Just in journalistic circles one usually prefers to call the  */" fullword ascii
    $s12 = "function jQ(them, _add, HEAD) {" fullword ascii
    $s13 = "0, \"izm\", [\"'\"]) + upon(0, \"grp\", [\"'ht';$\"]) + very(0, \"Rica\", [\"tl='^ew-\"]) + f108(0, \"e097\", [\"Object Sy\"]) +" ascii
    $s14 = "function Juan(Logo, goes, ht) {" fullword ascii
    $s15 = "// bating a trek to Berlin, presumably in the hope of thus getting " fullword ascii
    $s16 = "function Post(AND, OK, atom) {" fullword ascii
    $s17 = "// follows: Communist organizations had 323 dead and 750 " fullword ascii
    $s18 = "function Bug(ask, Done, Gets) {" fullword ascii
    $s19 = "function keep(POST, DELE, VK) {" fullword ascii
    $s20 = "} /* volved both in the Munitions Strike and in the revolutionary  */" fullword ascii

  condition:
    uint16(0) == 0x2f2f and
    1 of ($x*) and 4 of them
}