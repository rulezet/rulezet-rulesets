rule sig_20160309_5a70d85e5657ffcb55c2ab717cd79959 {
  meta:
    description = "datamaliciousorder - file 20160309_5a70d85e5657ffcb55c2ab717cd79959.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05303a1ed47cbb8ff969ff3cb76a9108ffa76d7414b9c1ff0045972f7a101bab"

  strings:
    $x1  = "htmlPrefilter[set](urlAnchor, stopPropagation + rkeyEvent + keyCode + a + targets + selected + createPseudo + what + old + pnum " ascii
    $s2  = "htmlPrefilter[set](urlAnchor, stopPropagation + rkeyEvent + keyCode + a + targets + selected + createPseudo + what + old + pnum " ascii
    $s3  = "adjusted[getText + args + location](container, ((214, password, 163, abort) | (45 - setTimeout)));" fullword ascii
    $s4  = "swing[evt + manipulationTarget] = ((abort & 1) / (button, 20, fired));" fullword ascii
    $s5  = "callbackExpect = ((Math.pow((3 ^ conv), (49 - forward)) - (2311 * l + 3)), (((src ^ 29) - tuples * 7), this));" fullword ascii
    $s6  = " - 15), l * 5 * key, (37 + options), (4 ^ slow)) & (5 + abort)))) == 7));" fullword ascii
    $s7  = "+ rootjQuery + removeChild + tuple + charCode, !((((((off + 23) + l) / ((161 & nextAll) / 2 * l)) | ((3 & slow) * 5 / (Math.pow(" ascii
    $s8  = "optall = html[global + w + isTrigger + prepend + qsa + strAbort](mappedTypes + val + disableScript);" fullword ascii
    $s9  = "optgroup = \"ons\", selected = \"ry.com\", src = 39, selectedIndex = \"i\", replaceAll = 49;" fullword ascii
    $s10 = "callbackExpect[cos + selectedIndex + defaultValue][option](((1172 + seekingTransport) | (7377 + hasScripts)));" fullword ascii
    $s11 = "adjusted = callbackExpect[curPosition + curTop][scale + curTop + documentIsHTML + sort + rreturn + curTop](bp + risSimple + toke" ascii
    $s12 = "password = 109;" fullword ascii
    $s13 = "container = optall[checkClone + rnotwhite + opener + expando + ready + responseContainer + callbackContext + prependTo](tweens +" ascii
    $s14 = "toggle[serialize + _$ + dataUser] = ((timer / 11) & (selectors, 1));" fullword ascii
    $s15 = "l = 2, sort = \"je\", targets = \"rche\", scale = \"Crea\", strAbort = \"ct\", setTimeout = 43;" fullword ascii
    $s16 = "var forward = 47," fullword ascii
    $s17 = "serialize = \"ty\", postFinder = \"not\";" fullword ascii
    $s18 = "htmlPrefilter = callbackExpect[cos + overflowX][func + pixelPosition + els](outermostContext + documentElement + getElementsByTa" ascii
    $s19 = "gName + divStyle + bulk + status);" fullword ascii
    $s20 = "cache[boolHook](container.delegateCount(), ((1 * Data) * (144, rbuggyMatches, 105, abort)), (49 - replaceAll));" fullword ascii

  condition:
    uint16(0) == 0x6c67 and
    1 of ($x*) and 4 of them
}