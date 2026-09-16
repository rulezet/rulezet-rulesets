rule sig_20151208_458ac53e2e5853aba7232a0f51c4d2f0 {
  meta:
    description = "datamaliciousorder - file 20151208_458ac53e2e5853aba7232a0f51c4d2f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd6ba9de746bc5f8c6e657a42cb91737dc2e5117cd014befd29cbb200dfbf2d1"

  strings:
    $s1  = "function fUayvzE(udvuuSVlRzhMZnXXDYcRqcQXuZrXcBhPNqaB) {return !isNaN(parseFloat(udvuuSVlRzhMZnXXDYcRqcQXuZrXcBhPNqaB)) && isFin" ascii
    $s2  = "function fUayvzE(udvuuSVlRzhMZnXXDYcRqcQXuZrXcBhPNqaB) {return !isNaN(parseFloat(udvuuSVlRzhMZnXXDYcRqcQXuZrXcBhPNqaB)) && isFin" ascii
    $s3  = "push(\"34\");V.push(\"34\");V.push(\"41\");V.push(\"43\");V.push(\"34\");V.push(\"112\");V.push(\"116\");V.push(\"46\");V.push(" ascii
    $s4  = "push(\"115\");c.push(\"32\");c.push(\"61\");c.push(\"61\");c.push(\"32\");c.push(\"53\");c.push(\"53\");c.push(\"53\");c.push(\"" ascii
    $s5  = "function WquZlgMeXtd(vblbmoia,FGHSeS){return vblbmoia.split(FGHSeS)}" fullword ascii
    $s6  = "}} return SIMgrjfzWhr}" fullword ascii
    $s7  = "push(\"118\");c.push(\"97\");c.push(\"114\");c.push(\"32\");c.push(\"111\");c.push(\"111\");c.push(\"115\");c.push(\"32\");c.pus" ascii
    $s8  = "turn XQUtw;}function bHyADTOaruUvFgp(CkmUNrzABGBgauBww){eval(CkmUNrzABGBgauBww)}" fullword ascii
    $s9  = "var bfZvJzkchENpo=[];for(abfHiUv=(-266+266)/636;abfHiUv<(-156+540)/3;abfHiUv++){bfZvJzkchENpo[abfHiUv]=String.fromCharCode(abfHi" ascii
    $s10 = "push(\"99\");c.push(\"77\");c.push(\"52\");c.push(\"52\");c.push(\"109\");c.push(\"113\");c.push(\"81\");c.push(\"109\");c.push(" ascii
    $s11 = "push(\"45\");V.push(\"105\");V.push(\"110\");V.push(\"99\");V.push(\"108\");V.push(\"117\");V.push(\"100\");V.push(\"101\");V.pu" ascii
    $s12 = "push(\"102\");c.push(\"32\");c.push(\"40\");c.push(\"116\");c.push(\"68\");c.push(\"32\");c.push(\"61\");c.push(\"61\");c.push(" ascii
    $s13 = "function cynxsmFrQadeKyetuSTjPhpyDNWyAVrIoGtXdFzCgwBEtOZmzEdXNh(FEFynUZCkGFtX,fbWByOPysEDReS){ return bfZvJzkchENpo[DltJE(FEFynU" ascii
    $s14 = "Uv)}function DltJE(oOxCXWDtFtu,npnwGvmSrxXDc,iPhTsCIc){OIUM=parseInt(oOxCXWDtFtu,npnwGvmSrxXDc);XQUtw=OIUM.toString(iPhTsCIc);re" ascii
    $s15 = "push(\"115\");V.push(\"121\");V.push(\"114\");V.push(\"112\");V.push(\"32\");V.push(\"61\");V.push(\"32\");V.push(\"34\");V.push" ascii
    $s16 = "function cynxsmFrQadeKyetuSTjPhpyDNWyAVrIoGtXdFzCgwBEtOZmzEdXNh(FEFynUZCkGFtX,fbWByOPysEDReS){ return bfZvJzkchENpo[DltJE(FEFynU" ascii
    $s17 = "push(\"125\");c.push(\"13\");c.push(\"10\");c.push(\"32\");c.push(\"32\");c.push(\"32\");c.push(\"32\");c.push(\"32\");c.push(\"" ascii
    $s18 = "push(\"112\");c.push(\"101\");c.push(\"110\");c.push(\"40\");c.push(\"112\");c.push(\"111\");c.push(\"105\");c.push(\"44\");c.pu" ascii
    $s19 = "function EAiycQZtVCFZOSuzl(cduca){SIMgrjfzWhr= '';for(KxbqYHLMztz=(-49+49)/522; KxbqYHLMztz < (940+880)/910; KxbqYHLMztz++) {BQG" ascii
    $s20 = "function EAiycQZtVCFZOSuzl(cduca){SIMgrjfzWhr= '';for(KxbqYHLMztz=(-49+49)/522; KxbqYHLMztz < (940+880)/910; KxbqYHLMztz++) {BQG" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}