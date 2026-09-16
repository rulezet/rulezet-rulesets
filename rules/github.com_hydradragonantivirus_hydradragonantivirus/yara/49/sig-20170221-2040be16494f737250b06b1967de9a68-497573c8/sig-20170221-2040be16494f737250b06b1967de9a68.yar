rule sig_20170221_2040be16494f737250b06b1967de9a68 {
  meta:
    description = "datamaliciousorder - file 20170221_2040be16494f737250b06b1967de9a68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "853999f6a36522568859950bcf86bf24dd13c5fd2159cc1fae64bf8e036daeb5"

  strings:
    $s1  = "return [new String(\"qw\"), new String(\"yvn\"), \"cmd.\", new String(\"ogdi\"), new String(\"apvy\"), new String(\"y\"), new St" ascii
    $s2  = "return [new String(\"qw\"), new String(\"yvn\"), \"cmd.\", new String(\"ogdi\"), new String(\"apvy\"), new String(\"y\"), new St" ascii
    $s3  = "ytqobudj() + cyqato() + pipa() + ndixhiqy() + akukwipd() + rcymici() + ofnukefr() + warivga() + hani() + avycg() + ofzis() + bex" ascii
    $s4  = ") + ofiwuhp() + secobbe() + ogiv() + zato() + twurmu(), new String(\"uro\"), new String(\"yde\"), new String(\"o\")][6], uckozga" ascii
    $s5  = "+ uwbaf() + iqoc() + acnepir() + tnojtudu() + ogmymsy() + buhsu() + fowikj() + nali() + wdutvo() + lyhnate() + rone() + figsiwj(" ascii
    $s6  = "var hizlev = [\"r\" + \"un\", new String(\"o\"), new String(\"s\"), new String(\"a\"), new String(\"b\"), new String(\"monw\"), " ascii
    $s7  = "var hizlev = [\"r\" + \"un\", new String(\"o\"), new String(\"s\"), new String(\"a\"), new String(\"b\"), new String(\"monw\"), " ascii
    $s8  = "var evcirero = [new String(\"ufr\"), new String(\"xvo\"), typeof XMLHttpRequest, new String(\"vu\"), new String(\"jsodg\"), new " ascii
    $s9  = "return [new String(\"q\"), new String(\"injy\"), new String(\"bu\"), \"pass\", new String(\"ej\"), new String(\"glorv\"), new St" ascii
    $s10 = "var evcirero = [new String(\"ufr\"), new String(\"xvo\"), typeof XMLHttpRequest, new String(\"vu\"), new String(\"jsodg\"), new " ascii
    $s11 = "return [new String(\"q\"), new String(\"injy\"), new String(\"bu\"), \"pass\", new String(\"ej\"), new String(\"glorv\"), new St" ascii
    $s12 = "return [new String(\"a\"), new String(\"ba\"), new String(\"je\"), new String(\"ge\"), new String(\"e\"), new String(\"zi\"), \"" ascii
    $s13 = "function epupeqab() {" fullword ascii
    $s14 = "return [new String(\"e\"), new String(\"edy\"), new String(\"wyt\"), \"+$eg\", new String(\"ukq\"), new String(\"otf\"), new Str" ascii
    $s15 = "ring(\"fi\"), new String(\"agl\"), new String(\"wcot\")][4];" fullword ascii
    $s16 = ", new String(\"y\")][5];" fullword ascii
    $s17 = "function jamxibi() {" fullword ascii
    $s18 = "return [new String(\"e\"), new String(\"edy\"), new String(\"wyt\"), \"+$eg\", new String(\"ukq\"), new String(\"otf\"), new Str" ascii
    $s19 = "return [new String(\"a\"), new String(\"x\"), new String(\"yvqi\"), \"vapp\", new String(\"zb\"), new String(\"xa\"), new String" ascii
    $s20 = "ew String(\"dqe\"), new String(\"zy\"), new String(\"unxy\")][3];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}