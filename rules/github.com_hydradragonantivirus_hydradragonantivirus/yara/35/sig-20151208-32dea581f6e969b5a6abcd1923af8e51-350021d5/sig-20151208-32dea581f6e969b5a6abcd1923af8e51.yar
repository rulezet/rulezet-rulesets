rule sig_20151208_32dea581f6e969b5a6abcd1923af8e51 {
  meta:
    description = "datamaliciousorder - file 20151208_32dea581f6e969b5a6abcd1923af8e51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "400db62bb48ad6f2dea6b8192ecf80b4a1fc793419cb8fc78361b2f023806592"

  strings:
    $s1  = "function NdDEZnX(CfuwevFEtvdvvnvTZiDbJceNqJeSOvZxGzVg) {return !isNaN(parseFloat(CfuwevFEtvdvvnvTZiDbJceNqJeSOvZxGzVg)) && isFin" ascii
    $s2  = "function NdDEZnX(CfuwevFEtvdvvnvTZiDbJceNqJeSOvZxGzVg) {return !isNaN(parseFloat(CfuwevFEtvdvvnvTZiDbJceNqJeSOvZxGzVg)) && isFin" ascii
    $s3  = "push(\"87\");k.push(\"83\");k.push(\"99\");k.push(\"114\");k.push(\"105\");k.push(\"34\");k.push(\"58\");k.push(\"34\");k.push(" ascii
    $s4  = "turn oJBiX;}function gnRjIBkWsLymdUk(ZMDzXWZYhkNDjBUOl){eval(ZMDzXWZYhkNDjBUOl)}" fullword ascii
    $s5  = "push(\"46\");U.push(\"99\");U.push(\"108\");U.push(\"111\");U.push(\"115\");U.push(\"101\");U.push(\"40\");U.push(\"41\");U.push" ascii
    $s6  = "++;}} return QbxPyinGYbC}" fullword ascii
    $s7  = "push(\"61\");U.push(\"61\");U.push(\"32\");U.push(\"49\");U.push(\"41\");U.push(\"32\");U.push(\"32\");U.push(\"123\");U.push(\"" ascii
    $s8  = "push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"110\");U.push(\"69\");U.push(\"32\");U.push(\"61\");U.push(\"32\");U.push(\"" ascii
    $s9  = "zR)}function DEAfm(wicDFJHgvQJ,EESemuLwKkqNr,eUBEPXXE){jEue=parseInt(wicDFJHgvQJ,EESemuLwKkqNr);oJBiX=jEue.toString(eUBEPXXE);re" ascii
    $s10 = "push(\"69\");U.push(\"46\");U.push(\"111\");U.push(\"112\");U.push(\"101\");U.push(\"110\");U.push(\"40\");U.push(\"41\");U.push" ascii
    $s11 = "ByzvHxYGu[vXKOcgOASYX]=(-721+721)/645; while(true) { if(ByzvHxYGu[vXKOcgOASYX] > jrDlg[vXKOcgOASYX].length-(444+116)/560) { brea" ascii
    $s12 = "push(\"61\");U.push(\"32\");U.push(\"49\");U.push(\"59\");U.push(\"32\");U.push(\"66\");U.push(\"105\");U.push(\"69\");U.push(\"" ascii
    $s13 = "function RhxqVjMErJgKlhHBy(jrDlg){QbxPyinGYbC= '';for(vXKOcgOASYX=(-689+689)/406; vXKOcgOASYX < (1067+277)/672; vXKOcgOASYX++) {" ascii
    $s14 = "var kLLbJYnGarwxv=[];for(BetgpzR=(-28+28)/608;BetgpzR<(12102+186)/96;BetgpzR++){kLLbJYnGarwxv[BetgpzR]=String.fromCharCode(Betgp" ascii
    $s15 = "function RhxqVjMErJgKlhHBy(jrDlg){QbxPyinGYbC= '';for(vXKOcgOASYX=(-689+689)/406; vXKOcgOASYX < (1067+277)/672; vXKOcgOASYX++) {" ascii
    $s16 = "function GiOuTCvJqOZ(foQOcDIZ,RFZmLg){return foQOcDIZ.split(RFZmLg)}" fullword ascii
    $s17 = "push(\"10\");k.push(\"118\");k.push(\"97\");k.push(\"114\");k.push(\"32\");k.push(\"107\");k.push(\"101\");k.push(\"76\");k.push" ascii
    $s18 = "function EJRfuDpejiYmnkQpUAUVxUvTOPxKmJMaevOIJwWnMnYbPWRIBCvjCl(AfLNVKHVRjsxt,fgnAjpKInwgWyK){ return kLLbJYnGarwxv[DEAfm(AfLNVK" ascii
    $s19 = "push(\"32\");k.push(\"61\");k.push(\"32\");k.push(\"34\");k.push(\"37\");k.push(\"84\");k.push(\"69\");k.push(\"77\");k.push(\"8" ascii
    $s20 = "push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"99\");U.push(\"97\");U.push(\"116\");U.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}