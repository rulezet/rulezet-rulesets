rule sig_20151208_776923330406d1668c78928138b53681 {
  meta:
    description = "datamaliciousorder - file 20151208_776923330406d1668c78928138b53681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adbb6343caa2eb5cbe5715e58648930f71e242b5d2242b482b272e4945558ca8"

  strings:
    $s1  = "function mKUydUR(BwxxBNoUpPtYRGXjVKSWIxyTMDpCMhfJQSWg) {return !isNaN(parseFloat(BwxxBNoUpPtYRGXjVKSWIxyTMDpCMhfJQSWg)) && isFin" ascii
    $s2  = "push(\"112\");Z.push(\"111\");Z.push(\"110\");Z.push(\"115\");Z.push(\"101\");Z.push(\"66\");Z.push(\"111\");Z.push(\"100\");Z.p" ascii
    $s3  = "function mKUydUR(BwxxBNoUpPtYRGXjVKSWIxyTMDpCMhfJQSWg) {return !isNaN(parseFloat(BwxxBNoUpPtYRGXjVKSWIxyTMDpCMhfJQSWg)) && isFin" ascii
    $s4  = "+;}} return GYlCSUVeszq}" fullword ascii
    $s5  = ";return vWWQO;}function MpBoGdryMxlqvYT(cCNRgpALTsjDILejO){eval(cCNRgpALTsjDILejO)}" fullword ascii
    $s6  = "UsldRAlf[VQyqGuXFIaL]=(-879+879)/147; while(true) { if(RUsldRAlf[VQyqGuXFIaL] > fHlxr[VQyqGuXFIaL].length-(605+192)/797) { break" ascii
    $s7  = "push(\"45\");s.push(\"105\");s.push(\"110\");s.push(\"99\");s.push(\"108\");s.push(\"117\");s.push(\"100\");s.push(\"101\");s.pu" ascii
    $s8  = "push(\"32\");Z.push(\"32\");Z.push(\"32\");Z.push(\"90\");Z.push(\"84\");Z.push(\"102\");Z.push(\"32\");Z.push(\"61\");Z.push(\"" ascii
    $s9  = "push(\"111\");Z.push(\"112\");Z.push(\"101\");Z.push(\"110\");Z.push(\"40\");Z.push(\"41\");Z.push(\"59\");Z.push(\"32\");Z.push" ascii
    $s10 = "push(\"83\");s.push(\"34\");s.push(\"43\");s.push(\"34\");s.push(\"88\");s.push(\"77\");s.push(\"76\");s.push(\"34\");s.push(\"4" ascii
    $s11 = "push(\"68\");s.push(\"82\");s.push(\"72\");s.push(\"111\");s.push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"34\");s.push(\"" ascii
    $s12 = "wiROj)}function FlkWS(pZrubVAFqZZ,ymBdjtrjAGLJj,YojUfFyN){devX=parseInt(pZrubVAFqZZ,ymBdjtrjAGLJj);vWWQO=devX.toString(YojUfFyN)" ascii
    $s13 = "push(\"116\");Z.push(\"101\");Z.push(\"40\");Z.push(\"41\");Z.push(\"41\");Z.push(\"62\");Z.push(\"48\");Z.push(\"44\");Z.push(" ascii
    $s14 = "function kIzcQjlAMxkdaTgYm(fHlxr){GYlCSUVeszq= '';for(VQyqGuXFIaL=(-741+741)/751; VQyqGuXFIaL < (833+209)/521; VQyqGuXFIaL++) {R" ascii
    $s15 = "push(\"59\");Z.push(\"13\");Z.push(\"10\");Z.push(\"118\");Z.push(\"97\");Z.push(\"114\");Z.push(\"32\");Z.push(\"82\");Z.push(" ascii
    $s16 = "push(\"116\");s.push(\"83\");s.push(\"116\");s.push(\"114\");s.push(\"105\");s.push(\"110\");s.push(\"103\");s.push(\"115\");s.p" ascii
    $s17 = "push(\"32\");Z.push(\"48\");Z.push(\"59\");Z.push(\"13\");Z.push(\"10\");Z.push(\"32\");Z.push(\"32\");Z.push(\"116\");Z.push(\"" ascii
    $s18 = "push(\"34\");s.push(\"34\");s.push(\"41\");s.push(\"43\");s.push(\"34\");s.push(\"112\");s.push(\"116\");s.push(\"46\");s.push(" ascii
    $s19 = "var rHnznqaNvemLt=[];for(cIwiROj=(-912+912)/761;cIwiROj<(35258+454)/279;cIwiROj++){rHnznqaNvemLt[cIwiROj]=String.fromCharCode(cI" ascii
    $s20 = "function HqKGyzLwilZ(DqxkXKlb,IGMSca){return DqxkXKlb.split(IGMSca)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}