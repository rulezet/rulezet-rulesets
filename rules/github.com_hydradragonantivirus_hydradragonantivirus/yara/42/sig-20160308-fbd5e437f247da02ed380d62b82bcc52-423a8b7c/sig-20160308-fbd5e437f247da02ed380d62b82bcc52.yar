rule sig_20160308_fbd5e437f247da02ed380d62b82bcc52 {
  meta:
    description = "datamaliciousorder - file 20160308_fbd5e437f247da02ed380d62b82bcc52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d455131266f9bb5b1ad7d1bb4c204020de72db25a3c4d4d957e60c67d60282bc"

  strings:
    $s1  = "n + setFilters + firingIndex + textContent + password;" fullword ascii
    $s2  = "queue = interval[booleans + unmatched + selected + addHandle + slideUp + removeChild + click](swing + rclickable) + pixelPositio" ascii
    $s3  = "while(qsa[returned + implementation + closest + border] < ((responseHeaders - 51) - (Math.pow(send, 2) - rjsonp))) {" fullword ascii
    $s4  = "domManip = (((46 / holdReady) + (1728 / isSuccess)), (((800 / self) & (Math.pow(14, writable) - 177)), this));" fullword ascii
    $s5  = "qsa = domManip[collection + throws + rmargin + hasCompare][XMLHttpRequest + width + getComputedStyle](identifier + col + cache);" ascii
    $s6  = "domManip[constructor + clearInterval][resolveWith + postSelector](((200 - currentValue), (202 - cleanData), (202 - animate)));" fullword ascii
    $s7  = "qsa[fixInput + slideUp](access, dataUser + active + sibling + createPositionalPseudo + prependTo + tween + isTrigger + factory +" ascii
    $s8  = "sourceIndex[trim] = ((Math.pow(parseJSON, 2) - removeAttribute), (59 * writable + 3), (tick ^ 1));" fullword ascii
    $s9  = "qsa[textContent + acceptData + unmatched]();" fullword ascii
    $s10 = "fontWeight[extend](queue.overwritten(), ((tick | 0) & (hasOwnProperty, 57, after, 1)), ((isSimulated / 30) - (optionSet & 7)));" fullword ascii
    $s11 = "password = \"cr\";" fullword ascii
    $s12 = "_ = 13, rts = \"veT\", rjsonp = 378, sibling = \":\", getComputedStyle = \"bject\", matchAnyContext = 21;" fullword ascii
    $s13 = "swing = \"%TEMP\";" fullword ascii
    $s14 = " id, !(rnumnonpx < ((((1 | (pattern + 0)) ^ ((tick / 4) / (attributes, 116, round))) + (Math.pow(((1 * pattern) * (84 / left)), " ascii
    $s15 = "(1 * writable)) - ((0 / adown) ^ (18 - _)))) + (((15 - truncate) & 0) | ((matchesSelector - 18) | (pattern ^ 0))))));" fullword ascii
    $s16 = "qsa[fixInput + slideUp](access, dataUser + active + sibling + createPositionalPseudo + prependTo + tween + isTrigger + factory +" ascii
    $s17 = "access = \"GET\"," fullword ascii
    $s18 = "extend = which + slideUp;" fullword ascii
    $s19 = "offsetHeight[append + jsonProp]();" fullword ascii
    $s20 = "queue = interval[booleans + unmatched + selected + addHandle + slideUp + removeChild + click](swing + rclickable) + pixelPositio" ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}