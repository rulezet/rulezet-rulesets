rule sig_20160307_55fb643a630803e9189d5c4004de4090 {
  meta:
    description = "datamaliciousorder - file 20160307_55fb643a630803e9189d5c4004de4090.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b74a058e1e3fcbf18f22d661976f9f40ce79c549cae6d5570a6dca3ffde43174"

  strings:
    $x1  = "file[dataType](ret, caption + token + ignored + Expr + outermostContext + selected + until + throws + getText, !(div == (Math.po" ascii
    $s2  = "n = finalValue[contextBackup + support + cleanData + PI + selected + source + rchecked + matchExpr](test + mappedTypes) + els + " ascii
    $s3  = "delegateType + delegateTarget + contents + sortDetached + markFunction;" fullword ascii
    $s4  = "selector[manipulationTarget + shift][checkDisplay + docElem](((2854 - pointerleave) / (5 * offset + 1)));" fullword ascii
    $s5  = "h.pow((((clientLeft, 492) / (disableScript + 3)) & ((scriptCharset & 13) | (set & 5))), (((wait - 13) * (offset & 3) + (Math.pow" ascii
    $s6  = "selector = (2 * (emptyStyle ^ 7) * (run ^ 2) * (run ^ 5), (((minWidth - 8) * (run | 4) + (rnoContent ^ 0)), this));" fullword ascii
    $s7  = "w(((((2 * getPropertyValue) / (139, set)) - ((4 & soFar) + 2 * offset * 2)) + (((run | 1) * opts) / (1 + run))), ((((76 + clazz)" ascii
    $s8  = "while (file[j + resolveWith] < (Math.pow((2 + opts), (1 * rnoContent)) - (6 - opts))) {" fullword ascii
    $s9  = "(set, 2) - minWidth)) - (105 / getAttribute) * (16 | response))) - (42 - getAttribute) * (3 & (offset | 0)) * (opts + (30 - reje" ascii
    $s10 = "setFilters = selector[next + once + slideToggle][head + adjustCSS + initialInUnit + param + tabIndex + actualDisplay](delegate +" ascii
    $s11 = "setFilters = selector[next + once + slideToggle][head + adjustCSS + initialInUnit + param + tabIndex + actualDisplay](delegate +" ascii
    $s12 = "ctWith)) * ((26 / bind) & (15 - bind))))));" fullword ascii
    $s13 = "getText = \"34\", contextBackup = \"Ex\", j = \"readys\", cleanData = \"v\", token = \"//so\", ret = \"GET\";" fullword ascii
    $s14 = "initialInUnit = \"a\", delegate = \"ADODB\", offset = 3, has = \"WScr\", manipulationTarget = \"WScri\";" fullword ascii
    $s15 = "file = selector[parseFromString + param][clearInterval + classes + cached + actualDisplay](unbind + Symbol + rheaders + firstDat" ascii
    $s16 = "file[dataType](ret, caption + token + ignored + Expr + outermostContext + selected + until + throws + getText, !(div == (Math.po" ascii
    $s17 = "file = selector[parseFromString + param][clearInterval + classes + cached + actualDisplay](unbind + Symbol + rheaders + firstDat" ascii
    $s18 = "swing[rmargin + selected + visibility] = ((1 | run) * (102, beforeunload, 199, run));" fullword ascii
    $s19 = "test = \"%TEMP\";" fullword ascii
    $s20 = "selector[has + handler][_jQuery + seekingTransport](((unshift / 33) & (curLeft + 2810)));" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    1 of ($x*) and 4 of them
}