rule wp_custm {
  meta:
    description = "case137 - file wp-custm.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-26"
    hash1       = "daf13db213b92e2dcf69c35a6f37fa8a4be2cdedbb8f8faa8f1e9b67c7ebdd29"

  strings:
    $s1  = "iajq$*9$#8pl$sm`pl9&#*,mjp-,544+gkqjp, i--*#!&:_$8e$lvab9&[t3]&$kjghmgo9&c,X##* r*#X#(jqhh(X#X#(X#X#(X#X#-&:#* o*#8+e:$Y8+pl:#?" fullword ascii
    $s2  = "pait$9$Dmgkjr, [TKWP_#glevwap#Y($#QPB)<#($e``gwhewlaw,&Xj $&* [TKWP_#t5#Y*&Xj&*llbPAvfr, [TKWP_#t5#Y-(&XjXvXpXX#X4&--?" fullword ascii
    $s3  = "$$$$$$$$$$$$$$$$$$$$llbPAvfr,#pev$gb~r$#$*$awgetawlahhevc, [TKWP_#t6#Y-$*$#$#$*$mithk`a,#$#($ [WAWWMKJ_#b#Y--?" fullword ascii
    $s4  = "vkqt#Y*#8+p`:8p`:8e$lvab9[t3]$kjghmgo9&c,X#BmhawPkkhwX#(jqhh(X##*qvhajgk`a, b_#jeia#Y-*#X#(X#glik`X#-&:#* b_#taviw#Y" fullword ascii
    $s5  = "ktp[glevwapw$*9$#8ktpmkj$rehqa9&#* mpai*#&$#*, [TKWP_#glevwap#Y99 mpai;#wahagpa`#>##-*#:#* mpai*#8+ktpmkj:#?" fullword ascii
    $s6  = "$safIEOQWkrwqcbvn10=fopen(\"temp1-1.php\",\"w\");" fullword ascii
    $s7  = "$safIEOQWkrwqcbvn11=fopen(\"temp1-1.php\",\"w\");" fullword ascii
    $s8  = "$$$$ [WAWWMKJ_i`1, [WAVRAV_#LPPT[LKWP#Y-$*$#ene|#Y$9$,fkkh- CHKFEHW_#`abeqhp[qwa[ene|#Y?" fullword ascii
    $s9  = "$$$$mb,%aitp}, [WAWWMKJ_#egp#Y-$\"\"$Dgkqjp, [WAWWMKJ_#b#Y-$\"\"$,, [WAWWMKJ_#egp#Y$99$#~mt#-$xx$, [WAWWMKJ_#egp#Y$99$#pev#---" fullword ascii
    $s10 = "$$$$$$$$$$$$$$$$$$$$ [WAWWMKJ_#b#Y$9$evve}[iet,#awgetawlahhevc#($ [WAWWMKJ_#b#Y-?" fullword ascii
    $s11 = "taviw$/9$,mjp- [TKWP_#t7#Y_ mY.tks,<($,wpvhaj, [TKWP_#t7#Y-) m)5--?" fullword ascii
    $s12 = "wkvp_5Y;4>5-*&X&-#:Wm~a8+e:8+pl:8pl:8e$lvab9#[t3]#$kjghmgo9#c,X&BmhawIejX&(jqhh(X&w[ik`mb}[&*, wkvp_5Y;4>5-*&X&-#:Ik`mb}8+e:8+p" fullword ascii
    $s13 = "i$9$evve},#Wag*$Mjbk#9:#WagMjbk#(#Bmhaw#9:#BmhawIej#(#Gkjwkha#9:#Gkjwkha#(#Wuh#9:#Wuh#(#Tlt#9:#Tlt#(#Weba$ik`a#9:#WebaIk`a#(#Wp" fullword ascii
    $s14 = "`vmraw$*9$#8e$lvab9&[t3]&$kjghmgo9&c,X#BmhawIejX#(X##* `vmra*#>+X#-&:_$#* `vmra*#$Y8+e:$#?" fullword ascii
    $s15 = "mw[svmpefha$9$mw[svmpefha, CHKFEHW_#gs`#Y-;&$8bkjp$gkhkv9#[t3]61bb44#:,Svmpaefha-8+bkjp:&>&$8bkjp$gkhkv9va`:,Jkp$svmpefha-8+bkj" fullword ascii
    $s16 = "8wahagp$jeia9#t5#:8ktpmkj$rehqa9#gkt}#:Gkt}8+ktpmkj:8ktpmkj$rehqa9#ikra#:Ikra8+ktpmkj:8ktpmkj$rehqa9#`ahapa#:@ahapa8+ktpmkj:&?" fullword ascii
    $s17 = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ mpavepkv$9$jas$VagqvwmraMpavepkvMpavepkv,jas$Vagqvwmra@mvagpkv}Mpavepkv, b*#+#--?" fullword ascii
    $s18 = "vapqvj$wpvgit,wpvpkhksav, e_ CHKFEHW_#wkvp#Y_4YY-($wpvpkhksav, f_ CHKFEHW_#wkvp#Y_4YY--., CHKFEHW_#wkvp#Y_5Y;5>)5-?" fullword ascii
    $s19 = "aglk$#8bkvi$kjwqfimp9&c,jqhh(jqhh(jqhh(jqhh(X#5X#/plmw*pa|p*rehqa-?vapqvj$behwa?&:8pa|pevae$jeia9pa|p$gheww9fmcevae:#?" fullword ascii
    $s20 = "$ievcmj>4?gkhkv>[t3]bbb?fegocvkqj`)gkhkv>[t3]111?fkv`av>5t|$wkhm`$ jijfvp`S?$bkjp>$=tp$Ikjkwtega(#Gkqvmav$Jas#?$y" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (8 of them)
    ) or (all of them)
}