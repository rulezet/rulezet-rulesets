rule sig_20160311_abb9d9f8d8f0557b191bad86c3459371 {
  meta:
    description = "datamaliciousorder - file 20160311_abb9d9f8d8f0557b191bad86c3459371.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48ff31833d57d8833982eb0a6e84e18e0e791bb3d3609e49b23285acbce7d70"

  strings:
    $s1  = "rnoContent[\"op\" + mapped](\"G\" + outermostContext, \"http\".notify() + setRequestHeader + \"ili\" + querySelectorAll + \".cz/" ascii
    $s2  = "otify() + currentTarget + \"r\" + content + \"sc\" + qsaError;" fullword ascii
    $s3  = "hasDuplicate = whitespace[tweens + \"and\" + postFilter + \"nment\".notify() + doc + \"s\"](percent + \"/\") + pointerleave + \"" ascii
    $s4  = "animate = 98, originalSettings = \"45\", processData = \"Resp\", setRequestHeader = \"://nob\", timers = 2, querySelectorAll = " ascii
    $s5  = "percent = \"%TEMP%\"," fullword ascii
    $s6  = " \"t4h\".notify() + originalSettings, !(((((setup | (243, animate, 1))) & ((outermost - 159), (current / 17), old)) * (((Math.po" ascii
    $s7  = "postFilter = \"Enviro\", old = 1, uid = \"0954\", content = \".\";" fullword ascii
    $s8  = "dirruns[cssShow + \"u\" + params](hasDuplicate.notify((1157 / fns)), (1 * (setup / 17)), ((propName - 26) / (onload + 5)));" fullword ascii
    $s9  = "function postDispatch() {" fullword ascii
    $s10 = "hasDuplicate = whitespace[tweens + \"and\" + postFilter + \"nment\".notify() + doc + \"s\"](percent + \"/\") + pointerleave + \"" ascii
    $s11 = "second[\"saveTo\" + nType](hasDuplicate, ((timers * 50) / timers * 5 * postSelector));" fullword ascii
    $s12 = "selected[innerText + \"yp\" + nodeIndex] = (1 & old);" fullword ascii
    $s13 = "second = byElement[container + \"pt\".notify()][siblingCheck + \"Obje\" + rmargin](\"ADODB\" + uniqueSort + \"eam\".notify());" fullword ascii
    $s14 = "second[firing + \"en\"]();" fullword ascii
    $s15 = "firing = \"op\", qsaError = \"r\";" fullword ascii
    $s16 = "detach = 15;" fullword ascii
    $s17 = "function bup() {" fullword ascii
    $s18 = "function easing() {" fullword ascii
    $s19 = "easing();" fullword ascii
    $s20 = "relative();" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}