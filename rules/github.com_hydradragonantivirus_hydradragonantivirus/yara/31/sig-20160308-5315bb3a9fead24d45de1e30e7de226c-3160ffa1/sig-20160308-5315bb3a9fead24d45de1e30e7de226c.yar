rule sig_20160308_5315bb3a9fead24d45de1e30e7de226c {
  meta:
    description = "datamaliciousorder - file 20160308_5315bb3a9fead24d45de1e30e7de226c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba0aafb351c56d1f13e072dc6cb6c3ecde5b9472aa63606b31c5f2a1bccba87c"

  strings:
    $s1  = "rbuggyQSA = (((204 - value) ^ (371 - password)), (((0 | string) * (Math.pow(5, owner) - 19) + (grep - 2)), this));" fullword ascii
    $s2  = "etag = css[emptyGet + stopPropagation + scriptCharset](attaches + memory + t + addToPrefiltersOrTransports);" fullword ascii
    $s3  = "module = etag[target + context + replaceChild + startTime + responses](statusCode + setMatchers) + winnow + hidden;" fullword ascii
    $s4  = "rcombinators = \"pe\", hidden = \".scr\", currentTime = \"nd\";" fullword ascii
    $s5  = "stopQueue[getBoundingClientRect + rquery + defer](module, ((1 | owner) & (8 - noBubble)));" fullword ascii
    $s6  = "empty = rbuggyQSA[marginLeft + replaceWith][tuples + compile + sortDetached](what + propName + list + ready);" fullword ascii
    $s7  = "rbuggyQSA[dirrunsUnique + optionSet][scrollTo + parseFromString + cur](((compare + 838) / (sortStable * 10)));" fullword ascii
    $s8  = "target = \"Exp\";" fullword ascii
    $s9  = "prepend = \"S\", setMatchers = \"MP%/\", startTime = \"ntStri\", isPropagationStopped = \"ave\", password = 134;" fullword ascii
    $s10 = "q + checkDisplay, !(owner < ((((3 + doAnimation) + (0 ^ grep)) & ((229, simulate, 50, inspect) - (22 + attachEvent))) ^ (((246, " ascii
    $s11 = "while(empty[unmatched + fadeToggle + binary + attributes] < ((grep) + 0)) {" fullword ascii
    $s12 = "rbuggyQSA[dirrunsUnique + optionSet][prepend + MAX_NEGATIVE + cur](((matchIndexes | 770) + (assert | 661)));" fullword ascii
    $s13 = "duration[prototype + rcombinators] = ((sortStable | 0) ^ doAnimation);" fullword ascii
    $s14 = "empty[height + toggle](setFilters + nonce, rquickExpr + rlocalProtocol + tweener + isPropagationStopped + createButtonPseudo + e" ascii
    $s15 = "stopQueue[removeData + attributes](empty[createTextNode + siblingCheck + key + iNoClone]);" fullword ascii
    $s16 = "eq = \"nl/099\", memory = \"ipt.S\", groups = 155, emptyGet = \"Creat\";" fullword ascii
    $s17 = "stopQueue = rbuggyQSA[marginLeft + curTop + calculatePosition + load][emptyGet + merge + load](matched + prepend + postMap + pro" ascii
    $s18 = "stopQueue = rbuggyQSA[marginLeft + curTop + calculatePosition + load][emptyGet + merge + load](matched + prepend + postMap + pro" ascii
    $s19 = "statusText[access + excess] = (25, doAnimation);" fullword ascii
    $s20 = "empty[setup + parseFromString + currentTime]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}