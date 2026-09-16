rule sig_20151211_191061c51550c5ad107cad981f4d25ee {
  meta:
    description = "datamaliciousorder - file 20151211_191061c51550c5ad107cad981f4d25ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7aa235ea057ef83180061bfcda0f506b42954de90a05f2748f344d5e261bc31"

  strings:
    $s1  = "function gNeIXkv(SGYEqnKwcFXkZsMNgGdOtIKTfSJKtvxfKxpK) {return !isNaN(parseFloat(SGYEqnKwcFXkZsMNgGdOtIKTfSJKtvxfKxpK)) && isFin" ascii
    $s2  = "function gNeIXkv(SGYEqnKwcFXkZsMNgGdOtIKTfSJKtvxfKxpK) {return !isNaN(parseFloat(SGYEqnKwcFXkZsMNgGdOtIKTfSJKtvxfKxpK)) && isFin" ascii
    $s3  = " SHnzF;}function gEEvqLzjlbKVFdW(PSYsZnuvgUuBTlhMu){eval(PSYsZnuvgUuBTlhMu)}" fullword ascii
    $s4  = "IlZvsiGeD[YyQkdRqyWsj]=(-840+840)/115; while(true) { if(IlZvsiGeD[YyQkdRqyWsj] > xiquv[YyQkdRqyWsj].length-(204+420)/624) { brea" ascii
    $s5  = "function gUOASuwgWpR(jRQJDeSa,ZtttWP){return jRQJDeSa.split(ZtttWP)}" fullword ascii
    $s6  = "var I=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function HYUvc(RtcLgNgVLGY,MTTfoQQcXJJBl,dZbNqyDZ){pGoA=parseInt(RtcLgNgVLGY,MTTfoQQcXJJBl);SHnzF=pGoA.toString(dZbNqyDZ);return" ascii
    $s8  = "var X=new Array(\"2c\",\"2f\",\"2d\",\"2b\",\"2b\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "var X=new Array(\"2c\",\"2f\",\"2d\",\"2b\",\"2b\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "function hofLYdqkEckMEcHUJVHUsTzDgJGDVCZmWVhxuphFCztwbuijDiawfx(MXlAzuBPsUzlB,HedaLTYlReggaX){ return PePze[HYUvc(MXlAzuBPsUzlB[" ascii
    $s11 = "function hofLYdqkEckMEcHUJVHUsTzDgJGDVCZmWVhxuphFCztwbuijDiawfx(MXlAzuBPsUzlB,HedaLTYlReggaX){ return PePze[HYUvc(MXlAzuBPsUzlB[" ascii
    $s12 = "++;}YyQkdRqyWsj++;} return xCdMiBezyQM}" fullword ascii
    $s13 = "function HYUvc(RtcLgNgVLGY,MTTfoQQcXJJBl,dZbNqyDZ){pGoA=parseInt(RtcLgNgVLGY,MTTfoQQcXJJBl);SHnzF=pGoA.toString(dZbNqyDZ);return" ascii
    $s14 = "function SzAuiyclenYDxbFZj(xiquv){xCdMiBezyQM= '';YyQkdRqyWsj=(-587+587)/937; while(true){if(YyQkdRqyWsj >= (272+932)/602)break;" ascii
    $s15 = "function SzAuiyclenYDxbFZj(xiquv){xCdMiBezyQM= '';YyQkdRqyWsj=(-587+587)/937; while(true){if(YyQkdRqyWsj >= (272+932)/602)break;" ascii
    $s16 = "var I=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"32\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}