rule sig_20160308_e5233090b1a6ca348f6566665926269d {
  meta:
    description = "datamaliciousorder - file 20160308_e5233090b1a6ca348f6566665926269d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7b0295f0a34ac836dbedc389687aec01312feeea55eca074dab2b7b97a8dfd8"

  strings:
    $s1  = "pageYOffset[rnoContent](originalProperties + rcheckableType, hover + mimeType + qsaError + ret + then + rclickable + class2type " ascii
    $s2  = "while(pageYOffset[el + getScript + v + transport] < (Math.pow((prevObject, 87, responseHeadersString, 3), (checked / 13)) - (res" ascii
    $s3  = "while(pageYOffset[el + getScript + v + transport] < (Math.pow((prevObject, 87, responseHeadersString, 3), (checked / 13)) - (res" ascii
    $s4  = "fnOver[expanded + createButtonPseudo][adown](((Math.pow(username, 2) - preexisting), (12 + createDocumentFragment)));" fullword ascii
    $s5  = "empty[index + thead + newDefer](maxIterations, ((105 ^ byElement), (117 + complete), (64 + dataFilter), 2));" fullword ascii
    $s6  = "d), (1 & firingIndex)))) - (((5 ^ append) * (3 & append) & (15 & getStyles)) ^ (((5 & compilerCache) - (105 / pdataCur)) | (88, " ascii
    $s7  = "+ find + Symbol + l + parent + rbuggyMatches + related, !(5 < (Math.pow((((firingIndex & 0) | ((getBoundingClientRect & 2) + (no" ascii
    $s8  = "hover = \"http:\"," fullword ascii
    $s9  = "pageYOffset[rnoContent](originalProperties + rcheckableType, hover + mimeType + qsaError + ret + then + rclickable + class2type " ascii
    $s10 = "deNameSelector / 20))) * ((append & (183, ontype, 2)) + (nodeNameSelector))), (((3, attrHandle, 11) * append * (42 - parse) - ((" ascii
    $s11 = "getStyles = 11, settings = \"ADOD\", complete = 51, dest = \"Expa\", expanded = \"WScrip\", html = \"ings\";" fullword ascii
    $s12 = "detach = \"%TEMP\";" fullword ascii
    $s13 = "pipe, 0))))));" fullword ascii
    $s14 = "maxIterations = originalOptions[dest + undelegate + optionSet + parts + classNames + lastModified + html](detach + init) + rscri" ascii
    $s15 = "disableScript = empty;" fullword ascii
    $s16 = "pipe = 158, options = 8;" fullword ascii
    $s17 = "text = disableScript;" fullword ascii
    $s18 = "xhr = fnOver[mouseenter + promise + _];" fullword ascii
    $s19 = "fnOver[expanded + createButtonPseudo][xhrFields + maxWidth](((6860 / specified), (24, setMatcher), (1061 ^ next)));" fullword ascii
    $s20 = "empty[isSimulated + invert]();" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}