rule sig_20160328_82c34f2dba458f5b96bd62497435f4f8 {
  meta:
    description = "datamaliciousorder - file 20160328_82c34f2dba458f5b96bd62497435f4f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87038de792c31cb310811beafb0c2b775a4969603566567d6c8e1ec0033e2065"

  strings:
    $x1  = "eval(parent(\"var%20siblings%20%3D%20%28%22WScrip%22%29%2C%20name%20%3D%20%28%22/Sq%22%29%2C%20overrideMimeType%20%3D%20%28%22WS" ascii
    $s2  = "reliableMarginLeftVal[siblings + \"t\"][clazz]((Math.pow((3869 & propFilter), (2 | relative)) - (385618 * getComputedStyle + 125" ascii
    $s3  = "reliableMarginLeftVal[siblings + \"t\"][clazz]((Math.pow((3869 & propFilter), (2 | relative)) - (385618 * getComputedStyle + 125" ascii
    $s4  = "optDisabled[overrideMimeType + \"ript\"][clazz]((Math.pow((_$ | 325), relative) - (24128785 | keyHooks)));" fullword ascii
    $s5  = "getBoundingClientRect(parent(\"parsed%28%22http%3A%22%20+%20serializeArray%20+%20%22bik%22%20+%20nidselect%20+%20%22tpl%22%20+%2" ascii
    $s6  = "getBoundingClientRect(parent(\"blur%20%3D%20tmp%5BoverrideMimeType%20+%20%22rip%22%20+%20radioValue%5D%5B%22Cre%22%20+%20wrap%20" ascii
    $s7  = "getBoundingClientRect(parent(\"rheader%20%3D%20%5BmatcherOut%20+%20%22.Ser%22%20+%20second%20+%20%22XMLHT%22%20+%20pipe%20+%20%2" ascii
    $s8  = "getBoundingClientRect(parent(\"rheader%20%3D%20%5BmatcherOut%20+%20%22.Ser%22%20+%20second%20+%20%22XMLHT%22%20+%20pipe%20+%20%2" ascii
    $s9  = "getBoundingClientRect(parent(\"blur%5Bfind%20+%20%22p%22%20+%20nid%5D%28%22GE%22%20+%20hooks%2C%20%22http%3A/%22%20+%20valuePart" ascii
    $s10 = "getBoundingClientRect(parent(\"blur%20%3D%20tmp%5BoverrideMimeType%20+%20%22rip%22%20+%20radioValue%5D%5B%22Cre%22%20+%20wrap%20" ascii
    $s11 = "for(version = ((rCRLF + -1) / (mouseHooks - 68)); version < rheader[\"length\"]; version++) {" fullword ascii
    $s12 = "z](((Math.pow(155, relative) - 23792) - (augmentWidthOrHeight | 133)));" fullword ascii
    $s13 = "function scriptCharset(disableScript, getStyles) {" fullword ascii
    $s14 = "function inArray(getScript) {" fullword ascii
    $s15 = "while(blur[\"rea\" + safeActiveElement + \"ate\"] != ((5 + checkClone) - (500 / params))) reliableMarginLeftVal[siblings + \"t\"" ascii
    $s16 = "getBoundingClientRect(parent(\"originalEvent%20%3D%20has%5B%22Expa%22%20+%20readyState%20+%20%22nvir%22%20+%20key%20+%20%22Str%2" ascii
    $s17 = "getBoundingClientRect(parent(\"originalEvent%20%3D%20has%5B%22Expa%22%20+%20readyState%20+%20%22nvir%22%20+%20key%20+%20%22Str%2" ascii
    $s18 = "function hidden(script, htmlPrefilter, matcherFromTokens) {" fullword ascii
    $s19 = "if(blur[\"stat\" + options] == ((nativeStatusText - 22))) {" fullword ascii
    $s20 = "while(blur[\"rea\" + safeActiveElement + \"ate\"] != ((5 + checkClone) - (500 / params))) reliableMarginLeftVal[siblings + \"t\"" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}