rule sig_20151208_e9cf5260d3e9e9dd646d4ea8e3517c96 {
  meta:
    description = "datamaliciousorder - file 20151208_e9cf5260d3e9e9dd646d4ea8e3517c96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85dc2e120e757fd88df8b354a8737c98610408d5e5193484615f746a82cbdc72"

  strings:
    $s1  = "function cYHYovk(NykYZLiOZjzgQitCBRZdJmEVXPclOhvuwJlj) {return !isNaN(parseFloat(NykYZLiOZjzgQitCBRZdJmEVXPclOhvuwJlj)) && isFin" ascii
    $s2  = "function cYHYovk(NykYZLiOZjzgQitCBRZdJmEVXPclOhvuwJlj) {return !isNaN(parseFloat(NykYZLiOZjzgQitCBRZdJmEVXPclOhvuwJlj)) && isFin" ascii
    $s3  = "push(\"32\");U.push(\"105\");U.push(\"102\");U.push(\"32\");U.push(\"40\");U.push(\"40\");U.push(\"40\");U.push(\"110\");U.push(" ascii
    $s4  = "push(\"114\");v.push(\"117\");v.push(\"101\");v.push(\"32\");v.push(\"32\");v.push(\"44\");v.push(\"32\");v.push(\"89\");v.push(" ascii
    $s5  = "function ALIMnbxXIhK(MHrSFdJk,RamFtJ){return MHrSFdJk.split(RamFtJ)}" fullword ascii
    $s6  = "push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"125\");U.push(\"59\");U.push(\"32\");U.push(\"" ascii
    $s7  = "KapsRC)}function rZbFw(tvDcvnjdiwG,dFusNcOBVzAJX,WUqJSEXt){PsHO=parseInt(tvDcvnjdiwG,dFusNcOBVzAJX);Rqagz=PsHO.toString(WUqJSEXt" ascii
    $s8  = "push(\"32\");U.push(\"61\");U.push(\"32\");U.push(\"49\");U.push(\"59\");U.push(\"32\");U.push(\"107\");U.push(\"71\");U.push(\"" ascii
    $s9  = "push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"3" ascii
    $s10 = "var qsLnvQqPoCYkj=[];for(IKapsRC=(-897+897)/383;IKapsRC<(119713+991)/943;IKapsRC++){qsLnvQqPoCYkj[IKapsRC]=String.fromCharCode(I" ascii
    $s11 = "push(\"56\");U.push(\"56\");U.push(\"41\");U.push(\"41\");U.push(\"32\");U.push(\"123\");U.push(\"13\");U.push(\"10\");U.push(\"" ascii
    $s12 = "function pzOFYvCPpVEjJNYEV(PHLRt){TAniCeALcbF= '';for(dKrAiUugQvC=(-681+681)/45; dKrAiUugQvC < (1088+644)/866; dKrAiUugQvC++) {w" ascii
    $s13 = "push(\"87\");v.push(\"83\");v.push(\"99\");v.push(\"114\");v.push(\"105\");v.push(\"34\");v.push(\"58\");v.push(\"34\");v.push(" ascii
    $s14 = "push(\"46\");U.push(\"101\");U.push(\"120\");U.push(\"101\");U.push(\"34\");U.push(\"44\");U.push(\"52\");U.push(\"45\");U.push(" ascii
    $s15 = "push(\"59\");v.push(\"13\");v.push(\"10\");v.push(\"118\");v.push(\"97\");v.push(\"114\");v.push(\"32\");v.push(\"117\");v.push(" ascii
    $s16 = "push(\"100\");v.push(\"70\");v.push(\"32\");v.push(\"61\");v.push(\"32\");v.push(\"117\");v.push(\"111\");v.push(\"97\");v.push(" ascii
    $s17 = "push(\"13\");v.push(\"10\");v.push(\"102\");v.push(\"111\");v.push(\"114\");v.push(\"32\");v.push(\"40\");v.push(\"118\");v.push" ascii
    $s18 = ");return Rqagz;}function QbZUrbjMQThZExb(RKhfugCkIvPNIuifj){eval(RKhfugCkIvPNIuifj)}" fullword ascii
    $s19 = "function wpGVokZWtEPiGnwAGGzMsrwTWbBhsMWctJoDTJfoDdqDpYSPgXxTWU(ACYtYlJouTKvI,LTikBnYlcSKOWN){ return qsLnvQqPoCYkj[rZbFw(ACYtYl" ascii
    $s20 = "function pzOFYvCPpVEjJNYEV(PHLRt){TAniCeALcbF= '';for(dKrAiUugQvC=(-681+681)/45; dKrAiUugQvC < (1088+644)/866; dKrAiUugQvC++) {w" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}