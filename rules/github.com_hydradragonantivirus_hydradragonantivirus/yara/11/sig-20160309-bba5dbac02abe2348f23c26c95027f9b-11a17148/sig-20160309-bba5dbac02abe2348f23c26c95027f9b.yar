rule sig_20160309_bba5dbac02abe2348f23c26c95027f9b {
  meta:
    description = "datamaliciousorder - file 20160309_bba5dbac02abe2348f23c26c95027f9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b911c3090625d179338e9fc17d7ef7be27da8d931f4b7272fde172ba0568fc83"

  strings:
    $x1  = "replaceAll[Deferred](isImmediatePropagationStopped + nextSibling, unbind + related + bulk + namespace + defaultDisplay + jqXHR +" ascii
    $s2  = "| ((divStyle - 18) | (access ^ 0))))) - (((postMap + (0 & access)) ^ ((Math.pow(107, matchIndexes) - 11305) / (currentTarget / 2" ascii
    $s3  = "replaceAll = pnum[getWidthOrHeight + children + matcherFromTokens + origName + opts][hooks + key + opts](rnotwhite + firstElemen" ascii
    $s4  = " (dest / 15)) * ((handleObj & 28) - (valHooks))), ((((1 & postMap) + (1 + -postMap)) & (1 + access)) + (((5 - ridentifier) * 1) " ascii
    $s5  = "responses = postDispatch[hooks + matchesSelector + support](getWidthOrHeight + dirruns + split + tbody);" fullword ascii
    $s6  = "pnum = ((47 + (postMap | 3)), (((hasFocus - 114), (postFilter | 167), (matchIndexes + 0)), this));" fullword ascii
    $s7  = " toArray + uniqueSort + rdisplayswap + matcher + fxNow + matchers, !((((((elemData & 13) * (postMap * 2)) - ((rjsonp - 38) * (po" ascii
    $s8  = "truncate[properties] = ((prevAll - 2), (postMap + 0));" fullword ascii
    $s9  = "computed[startLength](subordinate.newSelector(), ((postMap + -1) | (postMap * 0)), ((location / 21) * (postMap + -1)));" fullword ascii
    $s10 = "pnum[getWidthOrHeight + dirruns + opts][on](((focus & 12159) + setTimeout * 577));" fullword ascii
    $s11 = "tePositionalPseudo) | (242, swap, 106, ridentifier)) / 2 * (postMap * 2) * (createPositionalPseudo ^ 6)) & ((matchIndexes & 3) &" ascii
    $s12 = "(access | (102 / removeEvent))) - (((7 & dequeue) & (6 + access)) | (1 * matchIndexes) * 19))) == (Math.pow(((((width * 3 + crea" ascii
    $s13 = "isPropagationStopped = replaceAll[rscriptType + rclickable + visibility];" fullword ascii
    $s14 = "tChild + holdReady + fail);" fullword ascii
    $s15 = "subordinate = responses[attrHandle + trim + sibling + origCount + adjusted + textContent + rclickable](params + current) + progr" ascii
    $s16 = "subordinate = responses[attrHandle + trim + sibling + origCount + adjusted + textContent + rclickable](params + current) + progr" ascii
    $s17 = "stMap * 5) + (matchIndexes | 2))) * ((access ^ (1 ^ access)) * (1 + (access ^ 1)))) + ((((etag, 230, test) | (41, input, 11)) - " ascii
    $s18 = "replaceAll[Deferred](isImmediatePropagationStopped + nextSibling, unbind + related + bulk + namespace + defaultDisplay + jqXHR +" ascii
    $s19 = "scale[scripts + tweener]();" fullword ascii
    $s20 = "scripts = \"o\", returnValue = \"Run\", origCount = \"onmen\", always = \"cript\", notifyWith = \"r\", trim = \"xpand\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}