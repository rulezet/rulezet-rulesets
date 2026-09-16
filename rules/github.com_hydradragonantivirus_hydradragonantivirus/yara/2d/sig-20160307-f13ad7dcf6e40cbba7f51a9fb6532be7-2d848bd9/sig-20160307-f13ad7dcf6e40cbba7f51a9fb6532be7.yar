rule sig_20160307_f13ad7dcf6e40cbba7f51a9fb6532be7 {
  meta:
    description = "datamaliciousorder - file 20160307_f13ad7dcf6e40cbba7f51a9fb6532be7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee37a0844021c0be02e1d7e854007d1c7c012ce3f2cb477ce59ccb30c66f927"

  strings:
    $s1  = "siblingCheck[parents](arr, reject + JSON + initialInUnit + compare + rfxtypes + cssProps + origType + documentIsHTML + rmargin +" ascii
    $s2  = "(1 ^ getComputedStyle) * (Math.pow((Math.pow(3, getComputedStyle) - 5), (click & 2)) - (base / 44))) / (((properties - 47) * (co" ascii
    $s3  = "mbinator, 72, getComputedStyle) * (2 + wait) * ((1188 / cssFn), (Math.pow(196, getComputedStyle) - 38218), (lastModified, 4))) |" ascii
    $s4  = "rfocusMorph[dataTypes + self + expando](siblingCheck[rheaders + rbracket + run + setGlobalEval + rbuggyMatches + mouseHooks + co" ascii
    $s5  = "bindType = indirect[newContext + fixInput + MAX_NEGATIVE + setGlobalEval + progressContexts + outerCache + tmp + rfxtypes + chec" ascii
    $s6  = " (Math.pow(((Math.pow(tabIndex, 2) - msMatchesSelector) / (42 - originalOptions)), ((1326 / tick) - (180, overflow))) - (12 - fo" ascii
    $s7  = "context = ((281 & (get + 357)), (((conv2 & 27) - (fixHook ^ 20)), this));" fullword ascii
    $s8  = "rfocusMorph[always + blur](bindType, getComputedStyle);" fullword ascii
    $s9  = "rfocusMorph[dataTypes + self + expando](siblingCheck[rheaders + rbracket + run + setGlobalEval + rbuggyMatches + mouseHooks + co" ascii
    $s10 = "cusin) * (93 & close) * (1 * getComputedStyle))))));" fullword ascii
    $s11 = "kClone + callbackContext](iframe + keys) + display + head + ridentifier + slow;" fullword ascii
    $s12 = "siblingCheck = context[method + responseType][now + nextUntil + subtract + cssShow + expando + cssExpand](selectors + currentTim" ascii
    $s13 = "while(siblingCheck[handlers + pattern + num] < ((39 ^ rtrim) - 17 * click)) {" fullword ascii
    $s14 = "indirect = checkDisplay[cors + expando + cache + responseType](postFinder + register + qsaError + interval);" fullword ascii
    $s15 = " push_native, !(iNoClone < (((((19, name, 7) | (speed + 287)) & ((safeActiveElement - 22) | (replaceAll ^ 332))) ^ (mimeType) * " ascii
    $s16 = "not[slideToggle](bindType.unqueued(), (103, (wait ^ 0)), ((wait / 37) ^ (postMap, 0)));" fullword ascii
    $s17 = "Symbol[setMatchers + href] = ((valHooks - 45) + -(createDocumentFragment | 0));" fullword ascii
    $s18 = "siblingCheck[parents](arr, reject + JSON + initialInUnit + compare + rfxtypes + cssProps + origType + documentIsHTML + rmargin +" ascii
    $s19 = "undelegate = \"TP\", blur = \"File\", head = \"ks\", selectors = \"MSX\", now = \"C\", arr = \"GET\";" fullword ascii
    $s20 = "rfocusMorph = context[method + responseType][now + toggle + obj + destElements](genFx + has + option + dataTypeExpression);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}