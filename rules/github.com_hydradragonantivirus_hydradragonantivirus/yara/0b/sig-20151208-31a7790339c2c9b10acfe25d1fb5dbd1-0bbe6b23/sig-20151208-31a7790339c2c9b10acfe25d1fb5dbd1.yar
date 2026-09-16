rule sig_20151208_31a7790339c2c9b10acfe25d1fb5dbd1 {
  meta:
    description = "datamaliciousorder - file 20151208_31a7790339c2c9b10acfe25d1fb5dbd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eaa1e1a4745ba2c7d22fceedbe363b2841cdf5efa016d99fa937d529586ddaa"

  strings:
    $s1  = "function YXKjNJz(MNKwJkjXreAuQmQpiGJGpcKWiNtPMqQjLZII) {return !isNaN(parseFloat(MNKwJkjXreAuQmQpiGJGpcKWiNtPMqQjLZII)) && isFin" ascii
    $s2  = "function YXKjNJz(MNKwJkjXreAuQmQpiGJGpcKWiNtPMqQjLZII) {return !isNaN(parseFloat(MNKwJkjXreAuQmQpiGJGpcKWiNtPMqQjLZII)) && isFin" ascii
    $s3  = "var eXDJKkhJYlRRp=[];for(jWqzVTO=(-158+158)/220;jWqzVTO<(82204+484)/646;jWqzVTO++){eXDJKkhJYlRRp[jWqzVTO]=String.fromCharCode(jW" ascii
    $s4  = "function saEEhMcnrmKgvRnCNJAbEgPMJBeEVWbZPOZbyQbMLQVZBFYgWURcBf(vcKjMuWyrUCTM,bVPdAgnzzvdKIm){ return eXDJKkhJYlRRp[xxXuM(vcKjMu" ascii
    $s5  = "function pZMSzxLxugpqwmPVD(AqiuD){lvUCXIPPweG= '';for(yaMmJuJoFHn=(-60+60)/134; yaMmJuJoFHn < (885+435)/660; yaMmJuJoFHn++) {QLp" ascii
    $s6  = ";return zeMIq;}function uOzNwQiMKMmMUcu(FRZJGZYtIZKkZrAZl){eval(FRZJGZYtIZKkZrAZl)}" fullword ascii
    $s7  = "push(\"59\");l.push(\"13\");l.push(\"10\");l.push(\"118\");l.push(\"97\");l.push(\"114\");l.push(\"32\");l.push(\"114\");l.push(" ascii
    $s8  = "push(\"42\");X.push(\"47\");X.push(\"34\");X.push(\"46\");X.push(\"101\");X.push(\"120\");X.push(\"101\");X.push(\"34\");X.push(" ascii
    $s9  = "function pZMSzxLxugpqwmPVD(AqiuD){lvUCXIPPweG= '';for(yaMmJuJoFHn=(-60+60)/134; yaMmJuJoFHn < (885+435)/660; yaMmJuJoFHn++) {QLp" ascii
    $s10 = "function eMJgNQuNIzS(nPbNAlCX,FuqglH){return nPbNAlCX.split(FuqglH)}" fullword ascii
    $s11 = "push(\"61\");X.push(\"32\");X.push(\"48\");X.push(\"59\");X.push(\"13\");X.push(\"10\");X.push(\"32\");X.push(\"32\");X.push(\"1" ascii
    $s12 = "function saEEhMcnrmKgvRnCNJAbEgPMJBeEVWbZPOZbyQbMLQVZBFYgWURcBf(vcKjMuWyrUCTM,bVPdAgnzzvdKIm){ return eXDJKkhJYlRRp[xxXuM(vcKjMu" ascii
    $s13 = "push(\"83\");l.push(\"99\");l.push(\"114\");l.push(\"105\");l.push(\"34\");l.push(\"58\");l.push(\"34\");l.push(\"34\");l.push(" ascii
    $s14 = "push(\"32\");l.push(\"43\");l.push(\"32\");l.push(\"34\");l.push(\"66\");l.push(\"46\");l.push(\"83\");l.push(\"116\");l.push(\"" ascii
    $s15 = "qzVTO)}function xxXuM(vSNxTwOGplm,JfwsXhntvsbcQ,PXYGKOKl){PoOX=parseInt(vSNxTwOGplm,JfwsXhntvsbcQ);zeMIq=PoOX.toString(PXYGKOKl)" ascii
    $s16 = "push(\"47\");l.push(\"42\");l.push(\"98\");l.push(\"85\");l.push(\"81\");l.push(\"107\");l.push(\"51\");l.push(\"54\");l.push(\"" ascii
    $s17 = "push(\"32\");X.push(\"99\");X.push(\"97\");X.push(\"116\");X.push(\"99\");X.push(\"104\");X.push(\"32\");X.push(\"40\");X.push(" ascii
    $s18 = "DLJbPx[yaMmJuJoFHn]=(-159+159)/431; while(true) { if(QLpDLJbPx[yaMmJuJoFHn] > AqiuD[yaMmJuJoFHn].length-(469+353)/822) { break; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}