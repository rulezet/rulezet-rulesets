rule sig_20170125_549a4991958bc453a5793028558e6a28 {
  meta:
    description = "datamaliciousorder - file 20170125_549a4991958bc453a5793028558e6a28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ae1950fc42516a08ffba6ea6c6ee30ebd24747b7781a22dea46dd00515e62e2"

  strings:
    $s1  = "function lohsipopunhyltolafhacometybnacypalocudsutulaqguttahdossyhazosemcefgozatabgozkuru() {" fullword ascii
    $s2  = "return [ /*vvu*/ , \"C:\", /*gbyc*/ ];" fullword ascii
    $s3  = "return [ /*wekhy*/ , /*muvo*/ , WScript, /*nzazn*/ , /*yzwo*/ ][2];" fullword ascii
    $s4  = "function ujwohagrifytojoqylkupyhhunbyhostupgevjivxacroxwukvuchobjunbikyfyvylzut() {" fullword ascii
    $s5  = "function abgicipibledqeqsogqokokdoncoggihtaxusigevygkamretvycguzywoqxydjuxxenustiqlogbymukjoguxrobq() {" fullword ascii
    $s6  = "function rurelsuwfijsafubuwenitdotygoxmylelogybegirjixrostisydigtezfylaxu() {" fullword ascii
    $s7  = "return [\"Get\", /*ugu*/ , /*dhep*/ ];" fullword ascii
    $s8  = "return [ /*uqvu*/ , /*me*/ , /*zutge*/ , /*ocv*/ , \"Get\"];" fullword ascii
    $s9  = "function klyvkesexefsohiwyvfygtofmiwupyndiwxajegalbutjetsymhexujlipospylhy() {" fullword ascii
    $s10 = "function rabukmertedwacqacgamgyhokodykrebawezvaxhostuchiwiwbygfomikilysilg() {" fullword ascii
    $s11 = "return [ /*gro*/ , /*wagsy*/ , \"GET\"];" fullword ascii
    $s12 = "function qojomujzosoriverquckonhopdatytimbylisakwogetoscydtunabefofiwumasmekajydoqre() {" fullword ascii
    $s13 = "function ildursyhobrudsengimserogcyvorqanahraxadlefjazvatakwoxwivsospysijojlunyrsejgirilafrylesxujo() {" fullword ascii
    $s14 = "return [\"jdh\", /*plog*/ , /*amesj*/ , /*cby*/ ];" fullword ascii
    $s15 = "function vtanladqukxygledqodalogikhilhyzoxofywbehenuszekpebicinkancicokweqgonjynazel() {" fullword ascii
    $s16 = "return [\"run\", /*se*/ , /*esr*/ , /*ckup*/ , /*obtum*/ ];" fullword ascii
    $s17 = "function igemvihxyknobmozfatyvifvymizywvikakibmaruzoqvihvyvwaspypecanfozuqempekhefiwxy() {" fullword ascii
    $s18 = "function ejgaqybwucozotegemulmybhyhizmypxexvacfymizuwlohusofotilinaraflygircatpobugpizta() {" fullword ascii
    $s19 = "return [ /*qi*/ , \"At\", /*ah*/ ];" fullword ascii
    $s20 = "return [\"t;\", /*ftumlu*/ ];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}