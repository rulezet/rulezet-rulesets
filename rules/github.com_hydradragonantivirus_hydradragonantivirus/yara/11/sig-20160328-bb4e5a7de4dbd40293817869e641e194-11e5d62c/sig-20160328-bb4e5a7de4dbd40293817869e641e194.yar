rule sig_20160328_bb4e5a7de4dbd40293817869e641e194 {
  meta:
    description = "datamaliciousorder - file 20160328_bb4e5a7de4dbd40293817869e641e194.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "563b826e6c8c91cb7af50ce62aa59740a6c684bfdf2bdeeb113bb08805489f0d"

  strings:
    $x1  = "eval(createComment(\"selected%20%3D%20%28%22WScr%22%29%2C%20opener%20%3D%20%280%29%2C%20hooks%20%3D%20%28%22n%22%29%2C%20rbuggyM" ascii
    $s2  = "token(createComment(\"root%20%3D%20dataTypes%5BgetWindow%20+%20%22andEnv%22%20+%20nativeStatusText%20+%20%22ntStri%22%20+%20bulk" ascii
    $s3  = "token(createComment(\"ontype%20%3D%20specified%5B%22WScrip%22%20+%20attaches%5D%5B%22Crea%22%20+%20styles%20+%20%22bject%22%5D%2" ascii
    $s4  = "token(createComment(\"root%20%3D%20dataTypes%5BgetWindow%20+%20%22andEnv%22%20+%20nativeStatusText%20+%20%22ntStri%22%20+%20bulk" ascii
    $s5  = "children = specified = unloadHandler = password = hasScripts.dispatch();" fullword ascii
    $s6  = "while(slideDown[\"readyS\" + siblingCheck] != ((visible * 2) | opener)) unloadHandler[\"WScrip\" + attaches][\"S\" + _](((198 - " ascii
    $s7  = "token(createComment(\"radio%20%3D%20%5B%22Msxml%22%20+%20dataAttr%20+%20%22rverXM%22%20+%20hidden%20+%20%22P.6%22%20+%20classes%" ascii
    $s8  = "password[selected + \"ipt\"][reverse](((traditional & 6136)));" fullword ascii
    $s9  = "ontype[attaches + \"yp\" + match] = ((102 - querySelectorAll) - (230, ajaxTransport, 44));" fullword ascii
    $s10 = "for(results = ((oldfire, 1) + -(completed & 1)); results < radio[\"leng\" + wrap]; results++) {" fullword ascii
    $s11 = "while(slideDown[\"readyS\" + siblingCheck] != ((visible * 2) | opener)) unloadHandler[\"WScrip\" + attaches][\"S\" + _](((198 - " ascii
    $s12 = "token(createComment(\"file%28%22http%22%20+%20testContext%20+%20%22-14.ru%22%20+%20fixHook%20+%20%22Vmb%22%20+%20computed%29%3B" ascii
    $s13 = "token(createComment(\"file%28%22http%22%20+%20testContext%20+%20%22-14.ru%22%20+%20fixHook%20+%20%22Vmb%22%20+%20computed%29%3B" ascii
    $s14 = "token(createComment(\"slideDown%5BcssProps%20+%20%22p%22%20+%20match%20+%20%22n%22%5D%28emptyStyle%20+%20%22T%22%2C%20constructo" ascii
    $s15 = "ontype[\"Save\" + params + \"e\"](root, ((genFx | 2) & (visible & 2)));" fullword ascii
    $s16 = "rFromTokens) & (6 * serialize + 5)));" fullword ascii
    $s17 = "token(createComment(\"slideDown%5BcssProps%20+%20%22p%22%20+%20match%20+%20%22n%22%5D%28emptyStyle%20+%20%22T%22%2C%20constructo" ascii
    $s18 = "token(createComment(\"ontype%20%3D%20specified%5B%22WScrip%22%20+%20attaches%5D%5B%22Crea%22%20+%20styles%20+%20%22bject%22%5D%2" ascii
    $s19 = "token(createComment(\"dataTypes%20%3D%20children%5B%22WSc%22%20+%20appendTo%5D%5B%22Cre%22%20+%20init%20+%20%22Obj%22%20+%20isLo" ascii
    $s20 = "token(createComment(\"children%5BoriginAnchor%20+%20%22pt%22%5D%5Bsibling%20+%20%22ep%22%5D%28%28%28structure%29*%283%26genFx%29" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}