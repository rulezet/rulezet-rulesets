rule sig_20160325_6c503cbf5c10baa7504b18f0bcbcce8d {
  meta:
    description = "datamaliciousorder - file 20160325_6c503cbf5c10baa7504b18f0bcbcce8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "247934464a16082013ce2854c61c18e4720ba77879a15a99bd3b1b913e471c1c"

  strings:
    $s1  = "memory[emptyGet + \"yp\" + sort] = ((identifier & 1) * identifier);" fullword ascii
    $s2  = "conv2[elemdisplay + \"l\" + sort + \"ep\"](((307 + start) & (Math.pow(7973, createPositionalPseudo) - 63560540)));" fullword ascii
    $s3  = "rbrace(simulate, replaceAll, emptyGet, computeStyleTests, click);" fullword ascii
    $s4  = "XMLHttpRequest[step + \"nd\"]();" fullword ascii
    $s5  = "conv2 = root[\"WScri\" + func];" fullword ascii
    $s6  = "var ajaxTransport = [][\"cons\" + original + \"r\"][nType + \"ype\"][resolve + \"rt\"][evt + \"ppl\" + n]();" fullword ascii
    $s7  = "function rheaders() {" fullword ascii
    $s8  = "removeClass = disconnectedMatch[\"Exp\" + addClass + \"nviro\" + max + \"ntStri\" + getAll](\"%TE\" + outermostContext) + \"clas" ascii
    $s9  = "requestHeaders(soFar);" fullword ascii
    $s10 = "function requestHeaders() {" fullword ascii
    $s11 = "disconnectedMatch = conv2[\"Crea\" + timers + \"ject\"](disabled + \"t.Shel\" + risSimple);" fullword ascii
    $s12 = "msg = removeAttribute = stopPropagation = root = pageX.i();" fullword ascii
    $s13 = "merge[rts](XMLHttpRequest[letter]);" fullword ascii
    $s14 = "var identifier = 1," fullword ascii
    $s15 = "unbind = \"writ\";" fullword ascii
    $s16 = "return ajaxTransport;" fullword ascii
    $s17 = "push_native(isReady, _, lastChild, animation);" fullword ascii
    $s18 = "createTween(cssPrefixes, risSimple, container, computeStyleTests, click);" fullword ascii
    $s19 = "animation = \"R\";" fullword ascii
    $s20 = "function rdisplayswap() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}