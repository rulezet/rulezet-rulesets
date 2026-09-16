rule sig_20160311_4c173964114fad0bd40533a6f4f773e6 {
  meta:
    description = "datamaliciousorder - file 20160311_4c173964114fad0bd40533a6f4f773e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3072bc6be4c9076cacd5365f3f7ce1a5db3d365d268b940b4baa17d7fde2ec69"

  strings:
    $s1  = "(((Math.pow(max, 2) - pageY) * (1 * onerror) + (1 & opener)), (2 | (set & 1))) - ((rdashAlpha, 173, elementMatchers) / (232, hid" ascii
    $s2  = "reverse = ((Math.pow((80 / siblingCheck), (1 * onerror)) - 2 * radio * 17), ((Math.pow(originalSettings, 2) - rnative) / (32 / o" ascii
    $s3  = " + blur + \"l/0\" + fnOver + \"7g5\", !((Math.pow((((69 / max) / ((14 & fnOut) + (Math.pow(7, onerror) - 40))) * ((keepData, 127" ascii
    $s4  = "reverse = ((Math.pow((80 / siblingCheck), (1 * onerror)) - 2 * radio * 17), ((Math.pow(originalSettings, 2) - rnative) / (32 / o" ascii
    $s5  = "pipe = reverse[\"WScri\" + isArrayLike][\"Crea\" + removeEvent + \"ject\".now()](fast + \".Strea\" + optgroup);" fullword ascii
    $s6  = "pipe[\"o\" + isXML + \"n\".now()]();" fullword ascii
    $s7  = "pipe[el + \"File\".now()](startTime, (set | 2));" fullword ascii
    $s8  = "var gotoEnd = \"%TEMP%\"," fullword ascii
    $s9  = "define[\"R\" + createPositionalPseudo + \"n\"](startTime.now(((opts + 116) - (set | 80))), ((opener + -1) / (setMatchers / 7)), " ascii
    $s10 = "define[\"R\" + createPositionalPseudo + \"n\"](startTime.now(((opts + 116) - (set | 80))), ((opener + -1) / (setMatchers / 7)), " ascii
    $s11 = "implementation[selected + \"yp\" + nextAll] = ((16 * onerror + 7) - (pdataOld + 25));" fullword ascii
    $s12 = "camel[overwritten + \"p\" + newContext](\"GE\" + elem, \"http:/\".now() + nodeValue + \"fumy\" + split + \"e.re\" + jsonProp + " ascii
    $s13 = "camel = reverse[focusin + \"pt\".now()][origFn + \"eObj\" + dataType](\"MSXM\" + compile + \"HTTP\".now());" fullword ascii
    $s14 = "ner + -(1 | opener)));" fullword ascii
    $s15 = "inPage = indirect[l + \"ate\" + resolveContexts + \"ect\".now()](size + \"ipt.\" + splice);" fullword ascii
    $s16 = "blingCheck, 2) | (specialEasing - 6)) * ((siblingCheck + 12) - (addClass + 1))), ((returned / 14) & (styles / 50))) - ((Math.pow" ascii
    $s17 = "startTime = inPage[\"Expan\" + string + \"onmen\".now() + reliableMarginLeftVal + \"ngs\"](gotoEnd + \"/\") + r20 + \"laz\".now(" ascii
    $s18 = "riginalSettings)), eval(\"t\" + stop + \"is\".now()));" fullword ascii
    $s19 = "startTime = inPage[\"Expan\" + string + \"onmen\".now() + reliableMarginLeftVal + \"ngs\"](gotoEnd + \"/\") + r20 + \"laz\".now(" ascii
    $s20 = "camel[overwritten + \"p\" + newContext](\"GE\" + elem, \"http:/\".now() + nodeValue + \"fumy\" + split + \"e.re\" + jsonProp + " ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}