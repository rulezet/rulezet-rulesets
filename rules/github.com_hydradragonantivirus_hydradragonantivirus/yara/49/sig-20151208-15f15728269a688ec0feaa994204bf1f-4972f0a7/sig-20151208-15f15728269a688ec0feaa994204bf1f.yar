rule sig_20151208_15f15728269a688ec0feaa994204bf1f {
  meta:
    description = "datamaliciousorder - file 20151208_15f15728269a688ec0feaa994204bf1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9481720df67a4b6d76ed804253bd7c9afca704325176f11611a3df6f0baee2d"

  strings:
    $s1  = "function UJoAHlChqsEUBBQxn(GWmxx){scMdpbymXuQ= '';for(ZOIJNtTaahD=(-893+893)/258; ZOIJNtTaahD < (829+663)/746; ZOIJNtTaahD++) {x" ascii
    $s2  = "function kKmHCBw(ZsfvYEoopkCDBbLzXNKGqOFbOaqAcxliwvOi) {return !isNaN(parseFloat(ZsfvYEoopkCDBbLzXNKGqOFbOaqAcxliwvOi)) && isFin" ascii
    $s3  = "function kKmHCBw(ZsfvYEoopkCDBbLzXNKGqOFbOaqAcxliwvOi) {return !isNaN(parseFloat(ZsfvYEoopkCDBbLzXNKGqOFbOaqAcxliwvOi)) && isFin" ascii
    $s4  = "function UJoAHlChqsEUBBQxn(GWmxx){scMdpbymXuQ= '';for(ZOIJNtTaahD=(-893+893)/258; ZOIJNtTaahD < (829+663)/746; ZOIJNtTaahD++) {x" ascii
    $s5  = "++;}} return scMdpbymXuQ}" fullword ascii
    $s6  = "push(\"41\");F.push(\"59\");F.push(\"32\");F.push(\"105\");F.push(\"102\");F.push(\"32\");F.push(\"40\");F.push(\"74\");F.push(" ascii
    $s7  = "push(\"10\");F.push(\"9\");F.push(\"105\");F.push(\"102\");F.push(\"32\");F.push(\"40\");F.push(\"107\");F.push(\"84\");F.push(" ascii
    $s8  = "push(\"45\");i.push(\"105\");i.push(\"110\");i.push(\"99\");i.push(\"108\");i.push(\"117\");i.push(\"100\");i.push(\"101\");i.pu" ascii
    $s9  = "push(\"111\");F.push(\"110\");F.push(\"32\");F.push(\"61\");F.push(\"32\");F.push(\"48\");F.push(\"59\");F.push(\"32\");F.push(" ascii
    $s10 = "push(\"9\");F.push(\"9\");F.push(\"125\");F.push(\"59\");F.push(\"32\");F.push(\"13\");F.push(\"10\");F.push(\"32\");F.push(\"32" ascii
    $s11 = "var yzdAHtpudVlds=[];for(ToqhIeB=(-119+119)/652;ToqhIeB<(55443+621)/438;ToqhIeB++){yzdAHtpudVlds[ToqhIeB]=String.fromCharCode(To" ascii
    $s12 = "zffDjvQh[ZOIJNtTaahD]=(-762+762)/352; while(true) { if(xzffDjvQh[ZOIJNtTaahD] > GWmxx[ZOIJNtTaahD].length-(-328+833)/505) { brea" ascii
    $s13 = "push(\"71\");F.push(\"90\");F.push(\"84\");F.push(\"71\");F.push(\"42\");F.push(\"47\");F.push(\"43\");F.push(\"117\");F.push(\"" ascii
    $s14 = "push(\"13\");F.push(\"10\");F.push(\"118\");F.push(\"97\");F.push(\"114\");F.push(\"32\");F.push(\"74\");F.push(\"71\");F.push(" ascii
    $s15 = "function uvIlZgXHPnEPfpJctXJBjjqghaknQsouCerVNDhmGqbrGIGdOckdhG(hjRAvVKNjPKdN,BqujisZVYLVcVw){ return yzdAHtpudVlds[qAEJE(hjRAvV" ascii
    $s16 = ";return LQBVZ;}function EQpOijhswLhMNxL(HYaNxkupyvaRnrQOg){eval(HYaNxkupyvaRnrQOg)}" fullword ascii
    $s17 = "push(\"54\");F.push(\"50\");F.push(\"56\");F.push(\"57\");F.push(\"53\");F.push(\"50\");F.push(\"44\");F.push(\"32\");F.push(\"3" ascii
    $s18 = "function uvIlZgXHPnEPfpJctXJBjjqghaknQsouCerVNDhmGqbrGIGdOckdhG(hjRAvVKNjPKdN,BqujisZVYLVcVw){ return yzdAHtpudVlds[qAEJE(hjRAvV" ascii
    $s19 = "push(\"115\");i.push(\"41\");i.push(\"59\");i.push(\"13\");i.push(\"10\");i.push(\"118\");i.push(\"97\");i.push(\"114\");i.push(" ascii
    $s20 = "push(\"32\");F.push(\"40\");F.push(\"107\");F.push(\"107\");F.push(\"46\");F.push(\"115\");F.push(\"116\");F.push(\"97\");F.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}