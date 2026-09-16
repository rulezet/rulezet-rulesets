rule sig_20151208_b631c090a8a7bd5a3571892f9aaf5099 {
  meta:
    description = "datamaliciousorder - file 20151208_b631c090a8a7bd5a3571892f9aaf5099.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f09b49ce96e56f214fd0bd24a5051f740a9ab15d1f89a947d456bda79af40891"

  strings:
    $s1  = "function WaacNyf(KwQIWpGLizvKUDaTHFUIIHdZRdTmbDwPMfSB) {return !isNaN(parseFloat(KwQIWpGLizvKUDaTHFUIIHdZRdTmbDwPMfSB)) && isFin" ascii
    $s2  = "function WaacNyf(KwQIWpGLizvKUDaTHFUIIHdZRdTmbDwPMfSB) {return !isNaN(parseFloat(KwQIWpGLizvKUDaTHFUIIHdZRdTmbDwPMfSB)) && isFin" ascii
    $s3  = "QOxIqaba[rmcXYEAPTCZ]=(-371+371)/413; while(true) { if(oQOxIqaba[rmcXYEAPTCZ] > Mlwvk[rmcXYEAPTCZ].length-(93+229)/322) { break;" ascii
    $s4  = "function yeSxkzUnsjwIFPZjy(Mlwvk){FNtCypcwfNh= '';for(rmcXYEAPTCZ=(-447+447)/58; rmcXYEAPTCZ < (-432+638)/103; rmcXYEAPTCZ++) {o" ascii
    $s5  = " return FNtCypcwfNh}" fullword ascii
    $s6  = "function CBhDMcjXLXvvTedyergvAYrbYhZypxaxwutXSSzqATFYSpXsTLXxdq(hCKoTIWcFAOaZ,XmGDypaDFUNeiG){ return BFTFCZpPdHmza[RbhwG(hCKoTI" ascii
    $s7  = "function yeSxkzUnsjwIFPZjy(Mlwvk){FNtCypcwfNh= '';for(rmcXYEAPTCZ=(-447+447)/58; rmcXYEAPTCZ < (-432+638)/103; rmcXYEAPTCZ++) {o" ascii
    $s8  = ";return EHGuk;}function EhRMIhJKRdgNAld(GSdazVSlGzjCZnLrJ){eval(GSdazVSlGzjCZnLrJ)}" fullword ascii
    $s9  = "push(\"32\");j.push(\"32\");j.push(\"99\");j.push(\"97\");j.push(\"116\");j.push(\"99\");j.push(\"104\");j.push(\"32\");j.push(" ascii
    $s10 = "function ecEZFXEnQyJ(EVOYIOPA,WDYMES){return EVOYIOPA.split(WDYMES)}" fullword ascii
    $s11 = "push(\"10\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"80\");j.push(\"6" ascii
    $s12 = "push(\"42\");j.push(\"105\");j.push(\"52\");j.push(\"56\");j.push(\"55\");j.push(\"52\");j.push(\"49\");j.push(\"82\");j.push(\"" ascii
    $s13 = "push(\"104\");j.push(\"32\");j.push(\"40\");j.push(\"99\");j.push(\"107\");j.push(\"41\");j.push(\"32\");j.push(\"32\");j.push(" ascii
    $s14 = "push(\"108\");A.push(\"34\");A.push(\"59\");A.push(\"13\");A.push(\"10\");A.push(\"118\");A.push(\"97\");A.push(\"114\");A.push(" ascii
    $s15 = "XyyUE)}function RbhwG(YxATvrTqCsU,eMAoxXmvLBGQi,XYanZFXC){fWBn=parseInt(YxATvrTqCsU,eMAoxXmvLBGQi);EHGuk=fWBn.toString(XYanZFXC)" ascii
    $s16 = "push(\"41\");A.push(\"59\");A.push(\"13\");A.push(\"10\");A.push(\"118\");A.push(\"97\");A.push(\"114\");A.push(\"32\");A.push(" ascii
    $s17 = "push(\"47\");A.push(\"42\");A.push(\"120\");A.push(\"117\");A.push(\"105\");A.push(\"50\");A.push(\"49\");A.push(\"48\");A.push(" ascii
    $s18 = "push(\"43\");A.push(\"40\");A.push(\"54\");A.push(\"57\");A.push(\"57\");A.push(\"50\");A.push(\"49\");A.push(\"49\");A.push(\"4" ascii
    $s19 = "var BFTFCZpPdHmza=[];for(nNXyyUE=(-812+812)/210;nNXyyUE<(50145+543)/396;nNXyyUE++){BFTFCZpPdHmza[nNXyyUE]=String.fromCharCode(nN" ascii
    $s20 = "function CBhDMcjXLXvvTedyergvAYrbYhZypxaxwutXSSzqATFYSpXsTLXxdq(hCKoTIWcFAOaZ,XmGDypaDFUNeiG){ return BFTFCZpPdHmza[RbhwG(hCKoTI" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}