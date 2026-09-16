rule sig_20151208_31875312b057c5b6b37e89e50933e92a {
  meta:
    description = "datamaliciousorder - file 20151208_31875312b057c5b6b37e89e50933e92a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9ebc4537a3e99820eb90b980593751fac5c11b2fe3db56fd5d8a7afd31c7a41"

  strings:
    $s1  = "function ciSjKRB(yjvDpBWlaGdAUkHtqJqKEzxSzWFyjaFsOIzC) {return !isNaN(parseFloat(yjvDpBWlaGdAUkHtqJqKEzxSzWFyjaFsOIzC)) && isFin" ascii
    $s2  = "function ciSjKRB(yjvDpBWlaGdAUkHtqJqKEzxSzWFyjaFsOIzC) {return !isNaN(parseFloat(yjvDpBWlaGdAUkHtqJqKEzxSzWFyjaFsOIzC)) && isFin" ascii
    $s3  = ";return lNJZs;}function xbVtHMkUbjnWmiF(ExmKLLpZVOXaEkgmy){eval(ExmKLLpZVOXaEkgmy)}" fullword ascii
    $s4  = "push(\"32\");E.push(\"61\");E.push(\"32\");E.push(\"48\");E.push(\"59\");E.push(\"13\");E.push(\"10\");E.push(\"32\");E.push(\"3" ascii
    $s5  = "function HqzKOySafHSRteGuF(lrNDV){beObJvEmoaq= '';for(khScrGjybDC=(-873+873)/498; khScrGjybDC < (-111+243)/66; khScrGjybDC++) {U" ascii
    $s6  = "push(\"32\");E.push(\"77\");E.push(\"68\");E.push(\"97\");E.push(\"46\");E.push(\"116\");E.push(\"121\");E.push(\"112\");E.push(" ascii
    $s7  = "+;}} return beObJvEmoaq}" fullword ascii
    $s8  = "function tzyqJEHnFiYQwZEVFtKZwxjgNBoXPaPlgxidBlKKLvgZGzpPLJacDW(LuQwRiYlInkom,vwfMXgLCVkPTaX){ return nwmqtkZaJdvfz[MbTbX(LuQwRi" ascii
    $s9  = "push(\"47\");t.push(\"42\");t.push(\"99\");t.push(\"106\");t.push(\"100\");t.push(\"77\");t.push(\"50\");t.push(\"50\");t.push(" ascii
    $s10 = "push(\"100\");E.push(\"121\");E.push(\"41\");E.push(\"59\");E.push(\"32\");E.push(\"105\");E.push(\"102\");E.push(\"32\");E.push" ascii
    $s11 = "push(\"56\");E.push(\"53\");E.push(\"85\");E.push(\"54\");E.push(\"89\");E.push(\"122\");E.push(\"42\");E.push(\"47\");E.push(\"" ascii
    $s12 = "GybfrHOa[khScrGjybDC]=(-359+359)/339; while(true) { if(UGybfrHOa[khScrGjybDC] > lrNDV[khScrGjybDC].length-(-489+652)/163) { brea" ascii
    $s13 = "function yvInDsvYnrs(BZDxIHIz,KPJdVZ){return BZDxIHIz.split(KPJdVZ)}" fullword ascii
    $s14 = "function HqzKOySafHSRteGuF(lrNDV){beObJvEmoaq= '';for(khScrGjybDC=(-873+873)/498; khScrGjybDC < (-111+243)/66; khScrGjybDC++) {U" ascii
    $s15 = "push(\"82\");E.push(\"46\");E.push(\"111\");E.push(\"112\");E.push(\"101\");E.push(\"110\");E.push(\"40\");E.push(\"112\");E.pus" ascii
    $s16 = "push(\"32\");E.push(\"116\");E.push(\"114\");E.push(\"121\");E.push(\"32\");E.push(\"32\");E.push(\"123\");E.push(\"13\");E.push" ascii
    $s17 = "function tzyqJEHnFiYQwZEVFtKZwxjgNBoXPaPlgxidBlKKLvgZGzpPLJacDW(LuQwRiYlInkom,vwfMXgLCVkPTaX){ return nwmqtkZaJdvfz[MbTbX(LuQwRi" ascii
    $s18 = "push(\"32\");t.push(\"75\");t.push(\"61\");t.push(\"66\");t.push(\"89\");t.push(\"70\");t.push(\"59\");t.push(\"32\");t.push(\"7" ascii
    $s19 = "var nwmqtkZaJdvfz=[];for(FsmSBFB=(-932+932)/181;FsmSBFB<(77505+831)/612;FsmSBFB++){nwmqtkZaJdvfz[FsmSBFB]=String.fromCharCode(Fs" ascii
    $s20 = "mSBFB)}function MbTbX(AoFvUzfYhLH,APJBgrdVwkCAt,IxEFTNYL){zPxq=parseInt(AoFvUzfYhLH,APJBgrdVwkCAt);lNJZs=zPxq.toString(IxEFTNYL)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}