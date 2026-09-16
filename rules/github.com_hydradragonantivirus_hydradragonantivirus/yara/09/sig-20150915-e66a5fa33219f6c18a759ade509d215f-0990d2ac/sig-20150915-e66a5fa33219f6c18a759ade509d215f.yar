rule sig_20150915_e66a5fa33219f6c18a759ade509d215f {
  meta:
    description = "datamaliciousorder - file 20150915_e66a5fa33219f6c18a759ade509d215f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51feb4e7af417b9ce750b68ab71a7cdf69dc42361ede7a7d9faf149901b180c0"

  strings:
    $s1  = "var str=\"5550575E060B0300050A240C160A0111160B14014A070B09\";function te940574() { return ' 1;'; }; function te803655() { return" ascii
    $s2  = "n 'pa'; }; /* var vii=te315685(); */ function te375039() { return 'ring'; }; function te1017963() { return '.Run'; }; function t" ascii
    $s3  = "* var vii=te833950(); */ function te1196553() { return '\"+'; }; /* var vii=te740228(); */ function te934621() { return 'dn ='; " ascii
    $s4  = "* var vii=te241114(); */ function te1291801() { return '}; i'; }; /* var vii=te570366(); */ /* var vii=te823754(); */ /* var vii" ascii
    $s5  = "vii=te217858(); */ function te595300() { return 'HTTP'; }; /* var vii=te909315(); */ function te226214() { return 'ew '; }; /* v" ascii
    $s6  = "{ return ' && '; }; /* var vii=te989003(); */ /* var vii=te681629(); */ function te1154882() { return '+\"/'; }; function te7322" ascii
    $s7  = "{ return 'veXO'; }; function te845326() { return ' = '; }; function te130966() { return 'com'; }; /* var vii=te366364(); */ /* v" ascii
    $s8  = "e860666(); */ /* var vii=te275896(); */ /* var vii=te461296(); */ function te875091() { return '.Res'; }; /* var vii=te716157();" ascii
    $s9  = ") { return 'http:'; }; /* var vii=te388879(); */ /* var vii=te518171(); */ /* var vii=te875563(); */ function te309556() { retur" ascii
    $s10 = "ii=te980848(); */ /* var vii=te390369(); */ function te351227() { return '%TE'; }; /* var vii=te736429(); */ /* var vii=te560328" ascii
    $s11 = "D'; }; function te136919() { return '\".sp'; }; /* var vii=te346371(); */ function te1071540() { return 'xa.'; }; function te114" ascii
    $s12 = "39540(); */ function te202402() { return ') { v'; }; /* var vii=te378720(); */ /* var vii=te533682(); */ function te827467() { r" ascii
    $s13 = "9634() { return '};'; }; function te994151() { return 'fn,'; }; /* var vii=te268038(); */ /* var vii=te191933(); */ function te4" ascii
    $s14 = "1'; }; /* var vii=te193244(); */ function te946527() { return ' xa.p'; }; function te1381096() { return '20'; }; /* var vii=te10" ascii
    $s15 = "3() { return 'io'; }; function te779843() { return 'bject'; }; /* var vii=te729146(); */ function te529817() { return ' ='; }; /" ascii
    $s16 = "n te535770() { return ' n'; }; /* var vii=te317419(); */ /* var vii=te324627(); */ function te636971() { return 'ng'; }; /* var " ascii
    $s17 = " te482193() { return '0)+'; }; function te369086() { return 'St'; }; /* var vii=te838657(); */ function te1309660() { return '= " ascii
    $s18 = "unction te1047728() { return '(e'; }; /* var vii=te805515(); */ /* var vii=te113839(); */ /* var vii=te608602(); */ /* var vii=t" ascii
    $s19 = "; */ function te345274() { return 'ngs(\"'; }; function te208355() { return 'ar ws'; }; /* var vii=te993260(); */ /* var vii=te7" ascii
    $s20 = "939023(); */ function te761984() { return 'Ac'; }; /* var vii=te577747(); */ function te166684() { return 'var '; }; function te" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}