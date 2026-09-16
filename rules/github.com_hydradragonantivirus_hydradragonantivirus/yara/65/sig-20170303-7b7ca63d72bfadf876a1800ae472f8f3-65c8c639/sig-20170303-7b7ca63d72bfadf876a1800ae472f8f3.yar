rule sig_20170303_7b7ca63d72bfadf876a1800ae472f8f3 {
  meta:
    description = "datamaliciousorder - file 20170303_7b7ca63d72bfadf876a1800ae472f8f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7f1c8e1bdd858406ffae662d40ed54ca2fd0f36cc8476fe37691031081d3bb"

  strings:
    $x1  = "eludehumz[[Number(0.17), \"r\" + \"u\" + \"n\", Number(1.33), Number(-1.29), Number(-1.24), Number(-1.18), Number(1.33)][1]]([Nu" ascii
    $s2  = "1.37), Number(1.27), Number(-1.17), \"cmd.exe\", Number(1.19), Number(-1.44), Number(1.24), Number(-1.35)]) + gkunaxna(\"ghimyna" ascii
    $s3  = "ijyvcihlopnysf\", [Number(0.18), Number(-1.25), Number(1.23), Number(-1.25), Number(1.18), \" /c \\\"po\", Number(0.21)]) + tler" ascii
    $s4  = "Number(-1.15), Number(1.46), \"v='^cut\", Number(1.22), Number(0.38), Number(-1.17), Number(-1.23), Number(-1.44)]) + yvvirc(\"v" ascii
    $s5  = "function yvvirc(pumase, lydu) {" fullword ascii
    $s6  = "-1.41), Number(1.37), Number(-1.21), Number(0.44)]) + sice(\"qawyfyqubpotryrzyhujrujte\", [Number(1.34), Number(0.22), Number(0." ascii
    $s7  = "umber(-1.40)]) + elcyci(\"pippupzibudigupsesviviku\", [Number(1.34), Number(0.38), Number(-1.17), \"sw+$mpu\", Number(1.14), Num" ascii
    $s8  = "18), Number(-1.45), Number(-1.31), \"ylyqx+$\"]) + yrxyt(\"apebunrotwupem\", [Number(0.33), Number(1.33), \"isvylji\", Number(0." ascii
    $s9  = "lwe\", [Number(0.49), Number(0.34), Number(0.13), \"lbuvi+$\", Number(-1.39), Number(1.31), Number(1.32)]) + iqfofyrz(\"ugqunqed" ascii
    $s10 = "(1.20), \"='^ect \", Number(0.14), Number(-1.29), Number(1.15), Number(-1.21), Number(1.30)]) + oldit(\"vithutqanizavaxegequ\", " ascii
    $s11 = "mber(0.16)]) + uxiq(\"tqylaburote\", [Number(-1.14), Number(1.42), Number(-1.38), Number(1.30), \"^lexas.\", Number(0.28), Numbe" ascii
    $s12 = "'^ro\", Number(1.46), Number(1.43), Number(0.18), Number(-1.28), Number(0.23), Number(1.45)]) + exyzet(\"qnowgikixewitoqwyruzn\"" ascii
    $s13 = "Number(-1.24), Number(1.43)]) + ylmelo(\"nodvysjedegtagezy\", [\"on ($om\", Number(1.27), Number(-1.39), Number(-1.25), Number(1" ascii
    $s14 = "(0.44), Number(-1.41), Number(0.40), Number(1.22), Number(0.29)]) + nifwa(\"yfqare\", [Number(0.27), Number(-1.25), Number(1.48)" ascii
    $s15 = ".31), Number(0.36), \"+$ufwan\", Number(-1.13), Number(-1.50), Number(1.10)]) + zdystu(\"utyveknepowlomugosxi\", [Number(1.40), " ascii
    $s16 = "Number(-1.31), Number(1.15), Number(0.43), Number(1.35), Number(1.22), Number(1.45), Number(0.15), \"cess;';\"]) + hidrablo(\"eb" ascii
    $s17 = "), Number(0.43)]) + ipgivif(\"yqutxiwiqxoxje\", [Number(0.22), Number(0.42), Number(1.21), Number(-1.27), Number(-1.41), \"='^ $" ascii
    $s18 = "13), \"ss';$do\", Number(0.45)]) + miro(\"alyblun\", [Number(1.36), Number(1.42), Number(1.25), Number(0.15), Number(1.33), \"ky" ascii
    $s19 = "Number(-1.23), Number(1.47), Number(1.23), Number(1.15), Number(1.50), Number(1.12), \"';$ecgi\"]) + boqmuvd(\"qykgenjovgicysbir" ascii
    $s20 = ".39), Number(1.34)]) + ennyjxycs(\"ewolyhvurq\", [Number(1.46), Number(0.11), Number(-1.18), Number(0.10), Number(-1.26), \"(';$" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}