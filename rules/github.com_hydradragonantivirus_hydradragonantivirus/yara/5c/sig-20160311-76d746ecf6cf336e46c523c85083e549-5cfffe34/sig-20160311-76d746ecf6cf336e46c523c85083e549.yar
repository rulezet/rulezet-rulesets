rule sig_20160311_76d746ecf6cf336e46c523c85083e549 {
  meta:
    description = "datamaliciousorder - file 20160311_76d746ecf6cf336e46c523c85083e549.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeaf12e4beee6976d16a41d89bdd49b139ecf8d2c95d1fd38fd1ff536a930339"

  strings:
    $s1  = "setGlobalEval[setMatchers + \"p\" + types + \"n\"](pageY + \"T\".removeChild(), originalSettings + \"://pe\" + slideToggle + \"y" ascii
    $s2  = "(transport | 12))) & ((rmargin & 63) - (noCloneChecked & 45))) + ((((responseHeadersString, 1419) / (progressContexts * 1)) / ((" ascii
    $s3  = "atcherOut + \"ublika\".removeChild() + fail + \"h867g5\", !(6 < (((((tmp | 1052) / (postFilter, 144, then, 31)) | siblings) / ((" ascii
    $s4  = "checkContext[keyCode + \"u\".removeChild() + queue](cssPrefixes.removeChild(((Math.pow(simulate, 2) - createOptions) & (29 * cre" ascii
    $s5  = "checkContext[keyCode + \"u\".removeChild() + queue](cssPrefixes.removeChild(((Math.pow(simulate, 2) - createOptions) & (29 * cre" ascii
    $s6  = "- (matchAnyContext / 44)) / ((stopped * 2) + (tokens / 2)))) * (((progressContexts * 3) * initialInUnit - ((195, expanded, 1) * " ascii
    $s7  = "function delegateTarget() {" fullword ascii
    $s8  = "ap = (((117 * proxy + 106) - (doAnimation + 70)), (Math.pow((hasClass / 48), (proxy + 0)) - (tweeners * 3 + selectors)), eval(\"" ascii
    $s9  = "ap = (((117 * proxy + 106) - (doAnimation + 70)), (Math.pow((hasClass / 48), (proxy + 0)) - (tweeners * 3 + selectors)), eval(\"" ascii
    $s10 = "srcElements[method + \"eToFi\" + getWindow](cssPrefixes, (progressContexts + 1));" fullword ascii
    $s11 = "size = \"WSc\", originalSettings = \"http\", responseHeadersString = 237, rmargin = 39, types = \"e\";" fullword ascii
    $s12 = "swing - 46) + (parsed + 9))) / (createPositionalPseudo * (1 * createPositionalPseudo) * (1 + progressContexts) * (9 / createPosi" ascii
    $s13 = "setGlobalEval = ap[\"WSc\" + reset + \"t\".removeChild()][createHTMLDocument + \"teObje\" + stopQueue](\"MSXML\" + scrollTop + " ascii
    $s14 = "cloneCopyEvent = ap[size + \"rip\" + readyWait];" fullword ascii
    $s15 = "srcElements = ap[size + \"ript\".removeChild()][pdataOld + \"eObjec\" + readyWait](\"ADOD\" + rcssNum + \"eam\".removeChild());" fullword ascii
    $s16 = "proxy = 2, pdataOld = \"Creat\", send = \"WScr\", expanded = 228, tabIndex = \".\";" fullword ascii
    $s17 = "rmouseEvent = cloneCopyEvent[\"Create\" + splice + \"ect\".removeChild()](send + \"ipt.Sh\" + speed);" fullword ascii
    $s18 = "setGlobalEval = ap[\"WSc\" + reset + \"t\".removeChild()][createHTMLDocument + \"teObje\" + stopQueue](\"MSXML\" + scrollTop + " ascii
    $s19 = "cssPrefixes = rmouseEvent[\"Expand\" + rfxtypes + \"ronme\".removeChild() + prevUntil + \"tring\" + replaceChild](\"%TEM\" + pre" ascii
    $s20 = "fail = \".pl/08\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}