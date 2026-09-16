rule sig_20160328_d6a490f0ad6e9b09dae7342e34a66d82 {
  meta:
    description = "datamaliciousorder - file 20160328_d6a490f0ad6e9b09dae7342e34a66d82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66c7b895755508c6467838b8bae48b0e8bc50d212ad851fa5845ecf6f2c0facb"

  strings:
    $x1  = "eval(matcher(\"rscriptType%20%3D%20%28%22tim.co%22%29%3B%20qsaError%20%3D%20%28%22un%22%29%3B%20trim%20%3D%20%28%22MLH%22%29%3B%" ascii
    $s2  = "slideToggle[nodeName + \"ipt\"][resolve + \"eep\"](((Math.pow(register, 2) - letter) / (1 * getWidthOrHeight)));" fullword ascii
    $s3  = "while (rbracket[\"readyS\" + constructor + \"e\"] != ((99, Data, 140, clearQueue) + (1 + -adjustCSS))) slideToggle[nodeName + \"" ascii
    $s4  = "while (rbracket[\"readyS\" + constructor + \"e\"] != ((99, Data, 140, clearQueue) + (1 + -adjustCSS))) slideToggle[nodeName + \"" ascii
    $s5  = "rbracket = temp[\"WSc\" + cssNumber][\"Creat\" + each + \"t\"](fnOut[elements]);" fullword ascii
    $s6  = "eval(matcher(\"rscriptType%20%3D%20%28%22tim.co%22%29%3B%20qsaError%20%3D%20%28%22un%22%29%3B%20trim%20%3D%20%28%22MLH%22%29%3B%" ascii
    $s7  = "function keyCode(scriptCharset) {" fullword ascii
    $s8  = "firing(dataUser, curElem, getWidthOrHeight, _jQuery, isPlainObject);" fullword ascii
    $s9  = "prevObject[\"ty\" + bySet] = ((stopPropagation * 3 + adjustCSS) / (38 - wrap));" fullword ascii
    $s10 = "[resolve + \"eep\"](((1 * raw) * (51 - MAX_NEGATIVE) * 2 * (evt, 19, raw)));" fullword ascii
    $s11 = "isBorderBox(matcher(\"prevObject%20%3D%20temp%5B%22WSc%22%20+%20actualDisplay%20+%20%22t%22%5D%5Bon%20+%20%22Obj%22%20+%20divSty" ascii
    $s12 = "slideToggle = tabIndex = rmargin = temp = off.status();" fullword ascii
    $s13 = "isBorderBox(matcher(\"prevObject%20%3D%20temp%5B%22WSc%22%20+%20actualDisplay%20+%20%22t%22%5D%5Bon%20+%20%22Obj%22%20+%20divSty" ascii
    $s14 = "isBorderBox(matcher(\"file%28%22http%3A%22%20+%20outermostContext%20+%20%22rimoz%22%20+%20parts%20+%20%22itim.c%22%20+%20respons" ascii
    $s15 = "isBorderBox(matcher(\"td%20%3D%20rmargin%5B%22WScr%22%20+%20rnoContent%5D%5B%22Creat%22%20+%20reliableMarginLeft%20+%20%22ject%2" ascii
    $s16 = "isBorderBox(matcher(\"rbracket%5Brcombinators%20+%20%22en%22%5D%28pointerenter%20+%20%22ET%22%2C%20id%20+%20%22/basar%22%20+%20c" ascii
    $s17 = "isBorderBox(matcher(\"td%20%3D%20rmargin%5B%22WScr%22%20+%20rnoContent%5D%5B%22Creat%22%20+%20reliableMarginLeft%20+%20%22ject%2" ascii
    $s18 = "function tokens() {" fullword ascii
    $s19 = "isBorderBox(matcher(\"rbracket%5Brcombinators%20+%20%22en%22%5D%28pointerenter%20+%20%22ET%22%2C%20id%20+%20%22/basar%22%20+%20c" ascii
    $s20 = "isBorderBox(matcher(\"file%28%22http%3A%22%20+%20outermostContext%20+%20%22rimoz%22%20+%20parts%20+%20%22itim.c%22%20+%20respons" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}