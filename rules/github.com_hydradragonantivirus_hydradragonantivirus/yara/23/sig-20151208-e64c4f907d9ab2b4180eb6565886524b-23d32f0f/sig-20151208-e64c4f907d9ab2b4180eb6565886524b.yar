rule sig_20151208_e64c4f907d9ab2b4180eb6565886524b {
  meta:
    description = "datamaliciousorder - file 20151208_e64c4f907d9ab2b4180eb6565886524b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a12b4fa39076964ad2c4492000c7458bbf352e73b63b72019b85b932d4b213f"

  strings:
    $s1  = "function cIHmYOD(wWwxjElwRHOwsRpdpBmHNCOapyCrRKIQLABB) {return !isNaN(parseFloat(wWwxjElwRHOwsRpdpBmHNCOapyCrRKIQLABB)) && isFin" ascii
    $s2  = "function cIHmYOD(wWwxjElwRHOwsRpdpBmHNCOapyCrRKIQLABB) {return !isNaN(parseFloat(wWwxjElwRHOwsRpdpBmHNCOapyCrRKIQLABB)) && isFin" ascii
    $s3  = "push(\"108\");k.push(\"117\");k.push(\"100\");k.push(\"101\");k.push(\"115\");k.push(\"47\");k.push(\"112\");k.push(\"111\");k.p" ascii
    $s4  = "push(\"59\");t.push(\"32\");t.push(\"88\");t.push(\"120\");t.push(\"85\");t.push(\"46\");t.push(\"119\");t.push(\"114\");t.push(" ascii
    $s5  = "function AXoJrygxfYIetwliJ(XbxqW){MbMgDjUFpNu= '';for(BQoMhQGpxhP=(-321+321)/971; BQoMhQGpxhP < (1244+558)/901; BQoMhQGpxhP++) {" ascii
    $s6  = "mjbf)}function jwSRi(LybUPWMYTqE,GIDrIlhhmUTIE,LeUHJguP){zJhh=parseInt(LybUPWMYTqE,GIDrIlhhmUTIE);TzaDt=zJhh.toString(LeUHJguP);" ascii
    $s7  = "push(\"59\");t.push(\"32\");t.push(\"13\");t.push(\"10\");t.push(\"32\");t.push(\"32\");t.push(\"32\");t.push(\"32\");t.push(\"3" ascii
    $s8  = "var mYTzjlRTZLISw=[];for(coamjbf=(-402+402)/432;coamjbf<(51937+31)/406;coamjbf++){mYTzjlRTZLISw[coamjbf]=String.fromCharCode(coa" ascii
    $s9  = "+;}} return MbMgDjUFpNu}" fullword ascii
    $s10 = "push(\"79\");k.push(\"46\");k.push(\"69\");k.push(\"120\");k.push(\"112\");k.push(\"97\");k.push(\"110\");k.push(\"100\");k.push" ascii
    $s11 = "molVBQnjS[BQoMhQGpxhP]=(-692+692)/846; while(true) { if(molVBQnjS[BQoMhQGpxhP] > XbxqW[BQoMhQGpxhP].length-(785+99)/884) { break" ascii
    $s12 = "function szFixBqmwTsqcWPochRVjAsfJJnAyBJdxpLgHYkGXdhsdZyFeraAVc(RQncTBNqPInir,YRTEsHVkBleRgG){ return mYTzjlRTZLISw[jwSRi(RQncTB" ascii
    $s13 = "push(\"108\");t.push(\"78\");t.push(\"32\");t.push(\"61\");t.push(\"32\");t.push(\"49\");t.push(\"59\");t.push(\"32\");t.push(\"" ascii
    $s14 = "push(\"95\");k.push(\"112\");k.push(\"97\");k.push(\"103\");k.push(\"101\");k.push(\"115\");k.push(\"95\");k.push(\"115\");k.pus" ascii
    $s15 = "push(\"110\");t.push(\"32\");t.push(\"61\");t.push(\"32\");t.push(\"48\");t.push(\"59\");t.push(\"32\");t.push(\"88\");t.push(\"" ascii
    $s16 = "push(\"121\");t.push(\"32\");t.push(\"32\");t.push(\"123\");t.push(\"13\");t.push(\"10\");t.push(\"32\");t.push(\"32\");t.push(" ascii
    $s17 = "function szFixBqmwTsqcWPochRVjAsfJJnAyBJdxpLgHYkGXdhsdZyFeraAVc(RQncTBNqPInir,YRTEsHVkBleRgG){ return mYTzjlRTZLISw[jwSRi(RQncTB" ascii
    $s18 = "function oVJASOrDGvA(WdfyILjM,YVmxCu){return WdfyILjM.split(YVmxCu)}" fullword ascii
    $s19 = "push(\"32\");t.push(\"118\");t.push(\"97\");t.push(\"114\");t.push(\"32\");t.push(\"108\");t.push(\"78\");t.push(\"32\");t.push(" ascii
    $s20 = "push(\"84\");k.push(\"86\");k.push(\"41\");k.push(\"59\");k.push(\"13\");k.push(\"10\");k.push(\"118\");k.push(\"97\");k.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}