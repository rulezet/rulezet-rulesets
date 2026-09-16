rule sig_20160313_aa4d2afad97ad1ad30fc8acc2083ce66 {
  meta:
    description = "datamaliciousorder - file 20160313_aa4d2afad97ad1ad30fc8acc2083ce66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b2839be648de18a7ea7890b9a9d518a2915ddf80b77d502a0e34fb4165efe08"

  strings:
    $s1  = "obj[tfoot + \"p\" + testContext + \"n\"](top + \"T\", overflowY + \"://ohe\" + xml + \"uyff.c\" + offsetParent + \"exe\", !(2 ==" ascii
    $s2  = " + 13) & (password * 2 + uniqueID)), (Math.pow((50 + cssNumber), (246, code, 171, apply)) - (8739 * apply + 848)), ((round * 4 +" ascii
    $s3  = "relative[getComputedStyle + \"p\" + testContext] = ((2 * uniqueID) / (62 - stored));" fullword ascii
    $s4  = "obj = this[what + \"rip\" + Symbol][\"Crea\" + wait + \"bject\"](evt + \"ML2.XM\" + processData + \"P\");" fullword ascii
    $s5  = " lastModified) / (Math.pow(3, apply) - 5))) - (((getById - 17) * (calculatePosition / 11) + apply) | (1 + -xhrSuccessStatus))) |" ascii
    $s6  = ")) / (((50 - status) * (23 - round) + 1) | ((soFar, 144, using, 0) / (Math.pow(when, 2) - context)))))));" fullword ascii
    $s7  = "source = scale[\"Crea\" + qsaError + \"ct\"](overrideMimeType + \"pt.Sh\" + node);" fullword ascii
    $s8  = "password = 54," fullword ascii
    $s9  = "_data = \"d\", status = 47, getComputedStyle = \"ty\", uniqueID = 15;" fullword ascii
    $s10 = "grep = this[\"WScr\" + max][\"Crea\" + wait + \"bject\"](matcherFromTokens + \"Strea\" + sortInput);" fullword ascii
    $s11 = "grep[list + \"eToF\" + nodeName](fns, ((2 | contains)));" fullword ascii
    $s12 = "fns = source[\"Expa\" + cloneNode + \"ronme\" + parseJSON + \"rin\" + uid](\"%TE\" + notify) + \"pre\" + isNumeric + \".\" + val" ascii
    $s13 = "obj[tfoot + \"p\" + testContext + \"n\"](top + \"T\", overflowY + \"://ohe\" + xml + \"uyff.c\" + offsetParent + \"exe\", !(2 ==" ascii
    $s14 = "fns = source[\"Expa\" + cloneNode + \"ronme\" + parseJSON + \"rin\" + uid](\"%TE\" + notify) + \"pre\" + isNumeric + \".\" + val" ascii
    $s15 = "rootjQuery = source;" fullword ascii
    $s16 = "compare[\"close\"]();" fullword ascii
    $s17 = "compare = grep;" fullword ascii
    $s18 = "apply = 2;" fullword ascii
    $s19 = "function win() {" fullword ascii
    $s20 = "function letterSpacing() {" fullword ascii

  condition:
    uint16(0) == 0x645f and
    8 of them
}