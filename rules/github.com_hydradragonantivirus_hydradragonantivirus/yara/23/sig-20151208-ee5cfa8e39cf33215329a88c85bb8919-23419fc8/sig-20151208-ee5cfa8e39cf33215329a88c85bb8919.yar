rule sig_20151208_ee5cfa8e39cf33215329a88c85bb8919 {
  meta:
    description = "datamaliciousorder - file 20151208_ee5cfa8e39cf33215329a88c85bb8919.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a289c06168760716bd684448e5e235f9625c62538439c8bdfa6abe9ee55fe8a"

  strings:
    $s1  = "function cxZMgGU(HDcsIjgArqLpBinCNBCGRbImqBsKxaVYDSrp) {return !isNaN(parseFloat(HDcsIjgArqLpBinCNBCGRbImqBsKxaVYDSrp)) && isFin" ascii
    $s2  = "function cxZMgGU(HDcsIjgArqLpBinCNBCGRbImqBsKxaVYDSrp) {return !isNaN(parseFloat(HDcsIjgArqLpBinCNBCGRbImqBsKxaVYDSrp)) && isFin" ascii
    $s3  = "push(\"76\");R.push(\"115\");R.push(\"120\");R.push(\"82\");R.push(\"90\");R.push(\"101\");R.push(\"43\");R.push(\"47\");R.push(" ascii
    $s4  = "var zcwmUpVdplCxR=[];for(DnRpCSw=(-444+444)/425;DnRpCSw<(99780+956)/787;DnRpCSw++){zcwmUpVdplCxR[DnRpCSw]=String.fromCharCode(Dn" ascii
    $s5  = "function aZhvQvGMWiQstWlvA(wgwZL){EWjiaSDmAVJ= '';for(QsbYZPONUfZ=(-997+997)/205; QsbYZPONUfZ < (631+523)/577; QsbYZPONUfZ++) {n" ascii
    $s6  = "push(\"116\");w.push(\"46\");w.push(\"67\");w.push(\"114\");w.push(\"101\");w.push(\"97\");w.push(\"116\");w.push(\"101\");w.pus" ascii
    $s7  = "push(\"120\");R.push(\"101\");R.push(\"34\");R.push(\"44\");R.push(\"52\");R.push(\"45\");R.push(\"50\");R.push(\"41\");R.push(" ascii
    $s8  = "YnVGoRVi[QsbYZPONUfZ]=(-216+216)/838; while(true) { if(nYnVGoRVi[QsbYZPONUfZ] > wgwZL[QsbYZPONUfZ].length-(603+161)/764) { break" ascii
    $s9  = "push(\"34\");w.push(\"88\");w.push(\"77\");w.push(\"76\");w.push(\"34\");w.push(\"43\");w.push(\"40\");w.push(\"54\");w.push(\"5" ascii
    $s10 = "function blBFDNoxMKO(vqvoYeZi,rcFiOg){return vqvoYeZi.split(rcFiOg)}" fullword ascii
    $s11 = "push(\"32\");R.push(\"32\");R.push(\"121\");R.push(\"70\");R.push(\"46\");R.push(\"47\");R.push(\"42\");R.push(\"100\");R.push(" ascii
    $s12 = "push(\"69\");w.push(\"120\");w.push(\"112\");w.push(\"97\");w.push(\"110\");w.push(\"100\");w.push(\"69\");w.push(\"110\");w.pus" ascii
    $s13 = "function aZhvQvGMWiQstWlvA(wgwZL){EWjiaSDmAVJ= '';for(QsbYZPONUfZ=(-997+997)/205; QsbYZPONUfZ < (631+523)/577; QsbYZPONUfZ++) {n" ascii
    $s14 = "function HlNHBgulDlTTMlhVyExbbQFldMYPjQNDdzTubXEHcUDHaLRSSVbGHN(WYDNXdDTbBqgV,svkTqDhjJySuuO){ return zcwmUpVdplCxR[YgdQo(WYDNXd" ascii
    $s15 = "push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"32\");R.push(\"1" ascii
    $s16 = "function HlNHBgulDlTTMlhVyExbbQFldMYPjQNDdzTubXEHcUDHaLRSSVbGHN(WYDNXdDTbBqgV,svkTqDhjJySuuO){ return zcwmUpVdplCxR[YgdQo(WYDNXd" ascii
    $s17 = "push(\"102\");R.push(\"32\");R.push(\"40\");R.push(\"40\");R.push(\"40\");R.push(\"110\");R.push(\"101\");R.push(\"119\");R.push" ascii
    $s18 = "}} return EWjiaSDmAVJ}" fullword ascii
    $s19 = "RpCSw)}function YgdQo(TtfjLLMlrrp,oHzOneUPTLdWf,rbijaEat){ZSNw=parseInt(TtfjLLMlrrp,oHzOneUPTLdWf);LUxxy=ZSNw.toString(rbijaEat)" ascii
    $s20 = ";return LUxxy;}function oUmMrKRZmTlsIAF(FQFwrWdXXuuQILFzu){eval(FQFwrWdXXuuQILFzu)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}