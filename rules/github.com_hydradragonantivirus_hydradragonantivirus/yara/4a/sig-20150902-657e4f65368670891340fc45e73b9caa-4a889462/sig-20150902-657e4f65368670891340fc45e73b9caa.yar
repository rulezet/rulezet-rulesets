rule sig_20150902_657e4f65368670891340fc45e73b9caa {
  meta:
    description = "datamaliciousorder - file 20150902_657e4f65368670891340fc45e73b9caa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1318b003e7877c568ace0ede35379810b4077f9eac965a92097d20b7403db0e"

  strings:
    $s1  = "var stroke=\"5557505E17050D0005240C160A0111160B14014A070B09\";function npn225d() { return '; '; }; function npn15d() { return 'm" ascii
    $s2  = "'r '; }; function npn12d() { return 's.'; }; function npn191d() { return '\"GET\"'; }; function npn25d() { return '.com\"'; }; f" ascii
    $s3  = "tion npn138d() { return 'a.typ'; }; function npn216d() { return 'h '; }; function npn178d() { return 'atc'; }; function npn109d(" ascii
    $s4  = "tion npn34d() { return '; i<b'; }; function npn101d() { return 'HTTP\"'; }; function npn179d() { return 'h (er'; }; function npn" ascii
    $s5  = "urn 'ar '; }; function npn206d() { return 'ke'; }; function npn74d() { return 'h.rou'; }; function npn224d() { return 'eak'; }; " ascii
    $s6  = "; function npn119d() { return ' && '; }; function npn158d() { return 'n = '; }; function npn185d() { return '}; '; }; function n" ascii
    $s7  = " return 'nd(M'; }; function npn213d() { return '); }'; }; function npn49d() { return '.She'; }; function npn222d() { return ' ==" ascii
    $s8  = "n 'o.rea'; }; function npn122d() { return 'atus '; }; function npn98d() { return '\"MSX'; }; function npn197d() { return 'cu'; }" ascii
    $s9  = "on npn92d() { return '= new'; }; function npn10d() { return 'lan'; }; function npn64d() { return '%TE'; }; function npn76d() { r" ascii
    $s10 = "unction npn117d() { return 'ate '; }; function npn190d() { return 'en('; }; function npn211d() { return 'sen'; }; function npn16" ascii
    $s11 = "unction npn106d() { return 'state'; }; function npn27d() { return 'lit(\"'; }; function npn196d() { return 'do'; }; function npn" ascii
    $s12 = "function npn193d() { return 'p://\"'; }; function npn152d() { return 'xa.'; }; function npn207d() { return ', fal'; }; function " ascii
    $s13 = "r.'; }; function npn21d() { return 'nwr'; }; function npn112d() { return ') {'; }; function npn180d() { return ') {}'; }; functi" ascii
    $s14 = "ction npn38d() { return ' i++'; }; function npn144d() { return 'te(x'; }; function npn183d() { return 'os'; }; function npn107d(" ascii
    $s15 = "eturn 'ngs(\"'; }; function npn200d() { return '?rn'; }; function npn173d() { return 'Ru'; }; function npn103d() { return 'o.o';" ascii
    $s16 = ") { return ' f'; }; function npn93d() { return ' Act'; }; function npn136d() { return 'open'; }; function npn69d() { return 'g.f" ascii
    $s17 = "n146d() { return 'sp'; }; function npn51d() { return '\")'; }; function npn189d() { return 'o.op'; }; function npn140d() { retur" ascii
    $s18 = "on npn127d() { return '= new'; }; function npn153d() { return 'siz'; }; function npn33d() { return '=0'; }; function npn19d() { " ascii
    $s19 = "m d'; }; function npn220d() { return 'f ('; }; function npn62d() { return 'Stri'; }; function npn35d() { return '.l'; }; functio" ascii
    $s20 = "on('; }; function npn229d() { return '); dl'; }; function npn82d() { return '0000'; }; function npn13d() { return 'fr h'; }; fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}