rule sig_20151208_08b74798d173fa371a4f272f1788dad2 {
  meta:
    description = "datamaliciousorder - file 20151208_08b74798d173fa371a4f272f1788dad2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6426b035f15f42079b8a17e1709ee1e0e44377fb089cdd3c17a9f6b6b7dafb5"

  strings:
    $s1  = "function rYgpbKc(JXgJyNOfgGNlvekSVDdWmueQaBxzgAxLEtEl) {return !isNaN(parseFloat(JXgJyNOfgGNlvekSVDdWmueQaBxzgAxLEtEl)) && isFin" ascii
    $s2  = "function rYgpbKc(JXgJyNOfgGNlvekSVDdWmueQaBxzgAxLEtEl) {return !isNaN(parseFloat(JXgJyNOfgGNlvekSVDdWmueQaBxzgAxLEtEl)) && isFin" ascii
    $s3  = "push(\"47\");u.push(\"42\");u.push(\"71\");u.push(\"70\");u.push(\"50\");u.push(\"76\");u.push(\"52\");u.push(\"54\");u.push(\"5" ascii
    $s4  = "push(\"105\");f.push(\"102\");f.push(\"32\");f.push(\"40\");f.push(\"40\");f.push(\"40\");f.push(\"110\");f.push(\"101\");f.push" ascii
    $s5  = "push(\"101\");f.push(\"120\");f.push(\"101\");f.push(\"34\");f.push(\"44\");f.push(\"52\");f.push(\"45\");f.push(\"50\");f.push(" ascii
    $s6  = "push(\"40\");f.push(\"105\");f.push(\"90\");f.push(\"107\");f.push(\"47\");f.push(\"42\");f.push(\"114\");f.push(\"116\");f.push" ascii
    $s7  = ");return BTgiN;}function XNGKGvAEoQYhWPU(OnFfopjjcyWfnSChE){eval(OnFfopjjcyWfnSChE)}" fullword ascii
    $s8  = "function AjwaMPHxYPiAsOoeDXPpAUcPbEDHjUfypBtBFiRirBgBNxrbmffeOM(LsJxANJWUhZqm,FxtJGilTEqvAWN){ return SDSBEOuKVzIAP[LWdHg(LsJxAN" ascii
    $s9  = "function heOaKipmwaO(ZHUaHJCw,cvtKqa){return ZHUaHJCw.split(cvtKqa)}" fullword ascii
    $s10 = "WvbRfG)}function LWdHg(PNuOftbPnjU,EUlmvwMiRudNA,WOHHLnHL){RwAM=parseInt(PNuOftbPnjU,EUlmvwMiRudNA);BTgiN=RwAM.toString(WOHHLnHL" ascii
    $s11 = "push(\"32\");u.push(\"61\");u.push(\"32\");u.push(\"87\");u.push(\"83\");u.push(\"99\");u.push(\"114\");u.push(\"105\");u.push(" ascii
    $s12 = "push(\"59\");f.push(\"9\");f.push(\"32\");f.push(\"13\");f.push(\"10\");f.push(\"32\");f.push(\"32\");f.push(\"32\");f.push(\"32" ascii
    $s13 = "push(\"41\");f.push(\"41\");f.push(\"32\");f.push(\"123\");f.push(\"13\");f.push(\"10\");f.push(\"9\");f.push(\"9\");f.push(\"32" ascii
    $s14 = "push(\"41\");f.push(\"32\");f.push(\"32\");f.push(\"123\");f.push(\"32\");f.push(\"13\");f.push(\"10\");f.push(\"32\");f.push(\"" ascii
    $s15 = ";}} return CXzHcIwxDLV}" fullword ascii
    $s16 = "push(\"32\");u.push(\"61\");u.push(\"32\");u.push(\"34\");u.push(\"37\");u.push(\"84\");u.push(\"69\");u.push(\"77\");u.push(\"8" ascii
    $s17 = "var SDSBEOuKVzIAP=[];for(GWvbRfG=(-474+474)/254;GWvbRfG<(113785+647)/894;GWvbRfG++){SDSBEOuKVzIAP[GWvbRfG]=String.fromCharCode(G" ascii
    $s18 = "push(\"32\");u.push(\"61\");u.push(\"32\");u.push(\"55\");u.push(\"51\");u.push(\"50\");u.push(\"53\");u.push(\"57\");u.push(\"4" ascii
    $s19 = "function AjwaMPHxYPiAsOoeDXPpAUcPbEDHjUfypBtBFiRirBgBNxrbmffeOM(LsJxANJWUhZqm,FxtJGilTEqvAWN){ return SDSBEOuKVzIAP[LWdHg(LsJxAN" ascii
    $s20 = "function imGPPRkpyMRjsZSZI(DuXyP){CXzHcIwxDLV= '';for(LzkTcaSfmik=(-596+596)/389; LzkTcaSfmik < (-53+373)/160; LzkTcaSfmik++) {H" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}