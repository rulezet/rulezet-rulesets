rule sig_20160328_0da7c555e9d49085b5fd12cd3c734adc {
  meta:
    description = "datamaliciousorder - file 20160328_0da7c555e9d49085b5fd12cd3c734adc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5151684f59cf1f14569efb2e4d261eb76b690720e0b935fc3d412b0b6fc3c55"

  strings:
    $x1  = "eval(sel(\"progress%20%3D%20%28%22ironme%22%29%3Bversion%20%3D%20%28%222.XMLH%22%29%3BMAX_NEGATIVE%20%3D%20%28%22oFile%22%29%3B%" ascii
    $s2  = "binary(sel(\"byElement%20%3D%20readyList%5BtextContent%20+%20%22Env%22%20+%20progress%20+%20%22ntStri%22%20+%20getResponseHeader" ascii
    $s3  = "while(callbackContext[\"rea\" + teardown + \"e\"] != ((Math.pow(originalEvent, 2) - responseHeaders) | (3 + startLength))) check" ascii
    $s4  = "binary(sel(\"byElement%20%3D%20readyList%5BtextContent%20+%20%22Env%22%20+%20progress%20+%20%22ntStri%22%20+%20getResponseHeader" ascii
    $s5  = "binary(sel(\"adown%20%3D%20%5Btransport%20+%20%22.Serv%22%20+%20high%20+%20%22LHTTP.%22%20+%20_default%2C%20%22Msx%22%20+%20oMat" ascii
    $s6  = "for(globalEval = ((completed & 119), (startLength * 27), (firingIndex - 31), (body)); globalEval < adown[\"leng\" + dirruns]; gl" ascii
    $s7  = "for(globalEval = ((completed & 119), (startLength * 27), (firingIndex - 31), (body)); globalEval < adown[\"leng\" + dirruns]; gl" ascii
    $s8  = "binary(sel(\"colgroup%20%3D%20pageYOffset%5B%22WScr%22%20+%20preferredDoc%5D%5B%22Cre%22%20+%20pipe%20+%20%22Obje%22%20+%20proce" ascii
    $s9  = "binary(sel(\"context%5B%22WSc%22%20+%20unwrap%5D%5B%22Sle%22%20+%20_evalUrl%5D%28%28%28targets%7C672%29%26%28ap*6+hookFn%29%29%2" ascii
    $s10 = "binary(sel(\"context%5B%22WSc%22%20+%20unwrap%5D%5B%22Sle%22%20+%20_evalUrl%5D%28%28%28targets%7C672%29%26%28ap*6+hookFn%29%29%2" ascii
    $s11 = "while(callbackContext[\"rea\" + teardown + \"e\"] != ((Math.pow(originalEvent, 2) - responseHeaders) | (3 + startLength))) check" ascii
    $s12 = "if(callbackContext[\"st\" + old + \"s\"] == (Math.pow((27 * pointerenter + 24), (disable | 0)) - (createComment - 5837))) {" fullword ascii
    $s13 = "binary(sel(\"adown%20%3D%20%5Btransport%20+%20%22.Serv%22%20+%20high%20+%20%22LHTTP.%22%20+%20_default%2C%20%22Msx%22%20+%20oMat" ascii
    $s14 = "lements[nodeType + \"pt\"][beforeSend + \"e\" + nonce](((106, handleObjIn, 213, rnoContent) / (306 / PI)));" fullword ascii
    $s15 = "binary(sel(\"readyList%20%3D%20context%5B%22WSc%22%20+%20unwrap%5D%5B%22Cre%22%20+%20destElements%20+%20%22jec%22%20+%20setGloba" ascii
    $s16 = "readyList[result + \"un\"](byElement);" fullword ascii
    $s17 = "binary(sel(\"colgroup%20%3D%20pageYOffset%5B%22WScr%22%20+%20preferredDoc%5D%5B%22Cre%22%20+%20pipe%20+%20%22Obje%22%20+%20proce" ascii
    $s18 = "lass%20%3D%20%28%22Micro%22%29%2C%20ap%20%3D%20%281008%29%2C%20pipe%20%3D%20%28%22ate%22%29%2C%20isPropagationStopped%20%3D%20%2" ascii
    $s19 = "binary(sel(\"readyList%20%3D%20context%5B%22WSc%22%20+%20unwrap%5D%5B%22Cre%22%20+%20destElements%20+%20%22jec%22%20+%20setGloba" ascii
    $s20 = "blur(getResponseHeader);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}