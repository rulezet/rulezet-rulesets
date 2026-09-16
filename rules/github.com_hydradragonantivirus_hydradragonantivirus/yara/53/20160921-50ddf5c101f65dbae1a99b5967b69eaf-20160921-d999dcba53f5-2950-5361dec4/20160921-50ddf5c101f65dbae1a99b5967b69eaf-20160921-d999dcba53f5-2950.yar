rule _20160921_50ddf5c101f65dbae1a99b5967b69eaf_20160921_d999dcba53f5_2950 {
  meta:
    description = "datamaliciousorder - from files 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1 = "Gn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s2 = "turn \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})()" ascii
    $s4 = " f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"T" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\"" ascii
    $s6 = "(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})" ascii
    $s7 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}