rule sig_20151208_2874ff8351d03a3c75fe6b8d226fe50e {
  meta:
    description = "datamaliciousorder - file 20151208_2874ff8351d03a3c75fe6b8d226fe50e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaae7a2ad8e101312f4f693fcc4a55646cb7b547fb55137c9f544b0588e55e94"

  strings:
    $s1  = "function JaMQOxd(ngGTSMsPwhrqJwoYXmbxgmWpJWwkRaHJhjdq) {return !isNaN(parseFloat(ngGTSMsPwhrqJwoYXmbxgmWpJWwkRaHJhjdq)) && isFin" ascii
    $s2  = "function JaMQOxd(ngGTSMsPwhrqJwoYXmbxgmWpJWwkRaHJhjdq) {return !isNaN(parseFloat(ngGTSMsPwhrqJwoYXmbxgmWpJWwkRaHJhjdq)) && isFin" ascii
    $s3  = "function vCpOgRyFBkaHAuaQyZHxtlPaywHzlEixOkyhlzThcRAQmVdHBFwprl(VunFPdasVxaCs,abqfwCYfjKSMOE){ return itROCoWrECgol[RkQhk(VunFPd" ascii
    $s4  = "push(\"61\");H.push(\"32\");H.push(\"34\");H.push(\"37\");H.push(\"84\");H.push(\"69\");H.push(\"77\");H.push(\"80\");H.push(\"3" ascii
    $s5  = "var itROCoWrECgol=[];for(LRBfTxg=(-432+432)/407;LRBfTxg<(55653+539)/439;LRBfTxg++){itROCoWrECgol[LRBfTxg]=String.fromCharCode(LR" ascii
    $s6  = "push(\"32\");M.push(\"102\");M.push(\"59\");M.push(\"32\");M.push(\"98\");M.push(\"114\");M.push(\"101\");M.push(\"97\");M.push(" ascii
    $s7  = "push(\"47\");H.push(\"42\");H.push(\"85\");H.push(\"122\");H.push(\"80\");H.push(\"73\");H.push(\"52\");H.push(\"48\");H.push(\"" ascii
    $s8  = "push(\"41\");M.push(\"32\");M.push(\"123\");M.push(\"13\");M.push(\"10\");M.push(\"9\");M.push(\"9\");M.push(\"32\");M.push(\"32" ascii
    $s9  = "push(\"9\");M.push(\"125\");M.push(\"59\");M.push(\"32\");M.push(\"13\");M.push(\"10\");M.push(\"32\");M.push(\"32\");M.push(\"3" ascii
    $s10 = "fNugpFVgh[QyXWLsCORUQ]=(-884+884)/354; while(true) { if(fNugpFVgh[QyXWLsCORUQ] > KjzHd[QyXWLsCORUQ].length-(716+11)/727) { break" ascii
    $s11 = "push(\"83\");H.push(\"99\");H.push(\"114\");H.push(\"105\");H.push(\"34\");H.push(\"58\");H.push(\"34\");H.push(\"34\");H.push(" ascii
    $s12 = "function PueSbzDXYlAgNcUpY(KjzHd){MyhYYnYQXOt= '';for(QyXWLsCORUQ=(-887+887)/229; QyXWLsCORUQ < (-321+635)/157; QyXWLsCORUQ++) {" ascii
    $s13 = "push(\"123\");M.push(\"13\");M.push(\"10\");M.push(\"32\");M.push(\"32\");M.push(\"32\");M.push(\"32\");M.push(\"32\");M.push(\"" ascii
    $s14 = "function vCpOgRyFBkaHAuaQyZHxtlPaywHzlEixOkyhlzThcRAQmVdHBFwprl(VunFPdasVxaCs,abqfwCYfjKSMOE){ return itROCoWrECgol[RkQhk(VunFPd" ascii
    $s15 = "function PueSbzDXYlAgNcUpY(KjzHd){MyhYYnYQXOt= '';for(QyXWLsCORUQ=(-887+887)/229; QyXWLsCORUQ < (-321+635)/157; QyXWLsCORUQ++) {" ascii
    $s16 = ";return pcCfo;}function KFHjYwZYJNyStzO(VdOrmJgIqeOovurhL){eval(VdOrmJgIqeOovurhL)}" fullword ascii
    $s17 = "function dWXQrekvSIu(DqwUfPBa,ygykLY){return DqwUfPBa.split(ygykLY)}" fullword ascii
    $s18 = "push(\"106\");H.push(\"101\");H.push(\"99\");H.push(\"116\");H.push(\"40\");H.push(\"90\");H.push(\"70\");H.push(\"113\");H.push" ascii
    $s19 = "push(\"32\");M.push(\"61\");M.push(\"32\");M.push(\"34\");M.push(\"71\");M.push(\"69\");M.push(\"84\");M.push(\"34\");M.push(\"5" ascii
    $s20 = "push(\"32\");H.push(\"61\");H.push(\"32\");H.push(\"49\");H.push(\"59\");H.push(\"13\");H.push(\"10\");H.push(\"118\");H.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}