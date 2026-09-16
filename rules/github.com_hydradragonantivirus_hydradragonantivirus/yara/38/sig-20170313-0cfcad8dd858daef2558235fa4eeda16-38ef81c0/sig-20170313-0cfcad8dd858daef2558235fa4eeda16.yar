rule sig_20170313_0cfcad8dd858daef2558235fa4eeda16 {
  meta:
    description = "datamaliciousorder - file 20170313_0cfcad8dd858daef2558235fa4eeda16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc30225257d2113695c9eeef3b9e71508975fa59dbdf2c37fd3ec1a4bd54e4d1"

  strings:
    $x1  = "alpewdylgiv[[\"run\", Array(String), Array(String), Array(String), Array(String), Array(String)][0]]([Array(String), Array(Strin" ascii
    $x2  = "y(String), Array(String), Array(String), Array(String), \"cmd.exe /c \\\"powershe\", Array(String), Array(String)]) + umoxo(\"zh" ascii
    $s3  = "tring), \"^k.top/user.ph';$vod\", Array(String), Array(String), Array(String), Array(String)]) + ojapwi(\"yvuwatebyvysqurqogobzy" ascii
    $s4  = " \"'; Invoke-Expression\", Array(String), Array(String), Array(String), Array(String), Array(String), Array(String)]) + ixetax(" ascii
    $s5  = "), Array(String), Array(String), Array(String), \"f=1.gif'',$p';$ilecv\"]) + msecoqi(\"tupiqdymopnofapnaqnybryldiwbaknicylcurhax" ascii
    $s6  = "ifmybdukodd\", [Array(String), Array(String), Array(String), \"l';$bwimu='^tem.Net.\", Array(String), Array(String)]) + dmeczezc" ascii
    $s7  = "epexyfcepylatygyfafanicu\", [Array(String), Array(String), \"oa';$ryjo='^bhuh.exe\", Array(String), Array(String), Array(String)" ascii
    $s8  = "axgywkelhazwiziqam\", [Array(String), Array(String), Array(String), Array(String), Array(String), Array(String), \"olicy   Bypas" ascii
    $s9  = "alogemytannuqdoqyrfyhusewl\", 6, \"chobetxemqopelqyzoxifmotetipinydkibyxdymwabohjedsufbexels\", [Array(String), Array(String), A" ascii
    $s10 = "Array(String), Array(String)]) + blimarv(\"warotacpatiruvqytoffigijartuwigepvorefysafanenbivuhamyhizodnyqgaqnyb\", 0, \"vocnykby" ascii
    $s11 = "), Array(String), Array(String), Array(String), \"e='^rocess $path';$a\", Array(String), Array(String)]) + osqiqg(\"imqyhunypipx" ascii
    $s12 = "String), Array(String), Array(String), Array(String)]) + mawudh(\"ngytmikafuxixerabodirexfiqvuwapibohylhukxepneroj\", 3, \"havpu" ascii
    $s13 = ";$oqi\", Array(String), Array(String), Array(String)]) + xhovire(\"urtismugifehohnidaglirgebosagkepoveduguzalqovzogkopavocla\", " ascii
    $s14 = "String), Array(String)]) + awap(\"huzrorimgagewecilurerrarzefythyqfybedopkypogqipqamwotjijlaqdasi\", 2, \"azjigykogfenuvfatacygx" ascii
    $s15 = "String), Array(String), Array(String), \"qige+$ryjo+$pcewig+$\"]) + uguwpu(\"vyryzvyzyssurpykadazofinanalhygobiqkunyrihosuvzizte" ascii
    $s16 = "(String)]) + ftazi(\"tenifulojodifdubjuqufumewlyvhepysewivinmevixyqumkosw\", 3, \"bywgarpetodrybnubcithaqalaluzysowevencunniqtiz" ascii
    $s17 = " \"ewig='^ew-Object Sys\", Array(String), Array(String), Array(String), Array(String), Array(String)]) + dfobi(\"ukxinykosyryrul" ascii
    $s18 = "String), Array(String), Array(String), Array(String), Array(String), Array(String)]) + zasjumz(\"afyteqahbugrecvawtexxubyzagihka" ascii
    $s19 = "g), Array(String), Array(String), Array(String), \"ecution';$evbol='^p?\", Array(String)]) + ejfide(\"arguxzypypcogudpuxmoquqpek" ascii
    $s20 = "$dbyvmeps='^Set-Ex\", Array(String), Array(String), Array(String)]) + fnademm(\"ntajvepofozyvfifjizdidfegvecipvudubokirtaxniruwp" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}