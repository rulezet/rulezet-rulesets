rule sig_20151208_7c9a6b4df88518e35a8960a2444c596a {
  meta:
    description = "datamaliciousorder - file 20151208_7c9a6b4df88518e35a8960a2444c596a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd54aece4e0fb7dc540655b0807186fb2c9a8e76ef2028c0a897fdc5cad7e3d9"

  strings:
    $s1  = "function EUqSFSG(CMbYVbyWNgdxneOQnDFiYdDEminAtyOqKmuk) {return !isNaN(parseFloat(CMbYVbyWNgdxneOQnDFiYdDEminAtyOqKmuk)) && isFin" ascii
    $s2  = "function EUqSFSG(CMbYVbyWNgdxneOQnDFiYdDEminAtyOqKmuk) {return !isNaN(parseFloat(CMbYVbyWNgdxneOQnDFiYdDEminAtyOqKmuk)) && isFin" ascii
    $s3  = "push(\"92\");c.push(\"92\");c.push(\"34\");c.push(\"59\");c.push(\"13\");c.push(\"10\");c.push(\"118\");c.push(\"97\");c.push(\"" ascii
    $s4  = "push(\"10\");c.push(\"118\");c.push(\"97\");c.push(\"114\");c.push(\"32\");c.push(\"107\");c.push(\"102\");c.push(\"85\");c.push" ascii
    $s5  = "push(\"114\");c.push(\"105\");c.push(\"110\");c.push(\"103\");c.push(\"115\");c.push(\"40\");c.push(\"84\");c.push(\"76\");c.pus" ascii
    $s6  = "function cQqlfWKmWmVynnklf(JdESN){yXkNWIlstuK= '';for(sAyBsaVJlfY=(-831+831)/525; sAyBsaVJlfY < (1433+231)/832; sAyBsaVJlfY++) {" ascii
    $s7  = "++;}} return yXkNWIlstuK}" fullword ascii
    $s8  = "push(\"52\");C.push(\"50\");C.push(\"71\");C.push(\"81\");C.push(\"99\");C.push(\"106\");C.push(\"42\");C.push(\"47\");C.push(\"" ascii
    $s9  = "push(\"9\");C.push(\"32\");C.push(\"13\");C.push(\"10\");C.push(\"32\");C.push(\"32\");C.push(\"32\");C.push(\"32\");C.push(\"69" ascii
    $s10 = "push(\"99\");C.push(\"42\");C.push(\"47\");C.push(\"51\");C.push(\"45\");C.push(\"50\");C.push(\"44\");C.push(\"48\");C.push(\"4" ascii
    $s11 = ";return TBmxm;}function cRaIBHeSVOiNKEE(iGwiimmKuQwmxwExk){eval(iGwiimmKuQwmxwExk)}" fullword ascii
    $s12 = "function VmSJstVAWheoaCBjXxupxERjJDVdylVsmRGiKiUXUHeWNAOitaOtws(UGoISZSzbNuul,ROqibYkePRwbBC){ return vhuOuJjloVVfY[vHlmk(UGoISZ" ascii
    $s13 = "function vujEuiWBLOM(TEhrOrUT,xteqcW){return TEhrOrUT.split(xteqcW)}" fullword ascii
    $s14 = "push(\"46\");C.push(\"115\");C.push(\"101\");C.push(\"110\");C.push(\"100\");C.push(\"40\");C.push(\"41\");C.push(\"59\");C.push" ascii
    $s15 = "push(\"34\");c.push(\"88\");c.push(\"77\");c.push(\"76\");c.push(\"34\");c.push(\"43\");c.push(\"40\");c.push(\"55\");c.push(\"5" ascii
    $s16 = "function VmSJstVAWheoaCBjXxupxERjJDVdylVsmRGiKiUXUHeWNAOitaOtws(UGoISZSzbNuul,ROqibYkePRwbBC){ return vhuOuJjloVVfY[vHlmk(UGoISZ" ascii
    $s17 = "wZAgZ)}function vHlmk(uKEGwcMQtgB,HPKTgTveRuWzl,zTGLlhrz){fIDF=parseInt(uKEGwcMQtgB,HPKTgTveRuWzl);TBmxm=fIDF.toString(zTGLlhrz)" ascii
    $s18 = "var vhuOuJjloVVfY=[];for(TSwZAgZ=(-950+950)/552;TSwZAgZ<(89627+613)/705;TSwZAgZ++){vhuOuJjloVVfY[TSwZAgZ]=String.fromCharCode(TS" ascii
    $s19 = "push(\"32\");C.push(\"13\");C.push(\"10\");C.push(\"32\");C.push(\"32\");C.push(\"125\");C.push(\"13\");C.push(\"10\");C.push(\"" ascii
    $s20 = "function cQqlfWKmWmVynnklf(JdESN){yXkNWIlstuK= '';for(sAyBsaVJlfY=(-831+831)/525; sAyBsaVJlfY < (1433+231)/832; sAyBsaVJlfY++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}