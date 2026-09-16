rule MAL_FIN13_SIXPACK {
  meta:
    description   = "Matches strings found in SIXPACK ASPX webshell/tunneler used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
    last_modified = "2024-04-07"
    author        = "@petermstewart"
    DaysofYara    = "98/100"
    sha256        = "a3676562571f48c269027a069ecb08ee08973b7017f4965fa36a8fa34a18134e"
    ref           = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

  strings:
    $a1 = "Sending a packs..."
    $a2 = "Sending a pack..."
    $b1 = "nvc[\"host\"]"
    $b2 = "nvc[\"port\"]"
    $b3 = "nvc[\"timeout\"]"

  condition:
    filesize < 15KB and
    1 of ($a*) and
    all of ($b*)
}