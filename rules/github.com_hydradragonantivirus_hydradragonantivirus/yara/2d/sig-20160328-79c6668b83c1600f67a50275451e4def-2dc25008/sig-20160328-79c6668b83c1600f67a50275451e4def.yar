rule sig_20160328_79c6668b83c1600f67a50275451e4def {
  meta:
    description = "datamaliciousorder - file 20160328_79c6668b83c1600f67a50275451e4def.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5106bd95c4023d141e0791a5e21b2393f817187672a7ea7f9405b815d03e210b"

  strings:
    $s1  = "curLeft(onreadystatechange(\"event%20%3D%20%5BsortStable%20+%20%22ml2.Se%22%20+%20computed%20+%20%22rXM%22%20+%20handleObj%20+%2" ascii
    $s2  = "getElementsByName[addGetHookIf + \"pt\"][sortOrder + \"lee\" + byElement](((camelKey | 10), (Math.pow(tmp, 2) - rmultiDash), (Ma" ascii
    $s3  = "curLeft(onreadystatechange(\"container%20%3D%20getElementsByName%5B%22WScr%22%20+%20isSimulated%5D%5B%22Crea%22%20+%20css%20+%20" ascii
    $s4  = "while (pipe[\"ready\" + exports] != ((2 | shift) * (2 | shift))) replaceChild[\"WScri\" + originalOptions][\"Sleep\"](((2528 & i" ascii
    $s5  = "while (pipe[\"ready\" + exports] != ((2 | shift) * (2 | shift))) replaceChild[\"WScri\" + originalOptions][\"Sleep\"](((2528 & i" ascii
    $s6  = "curLeft(onreadystatechange(\"pipe%5Ball%20+%20%22p%22%20+%20nid%20+%20%22n%22%5D%28nodeValue%20+%20%22E%22%20+%20context%2C%20%2" ascii
    $s7  = "if (pipe[finalText + \"s\"] == ((7400 / originalEvent) | (5 * shift * 5 * shift * 2))) {" fullword ascii
    $s8  = "pipe[round + \"en\" + appendTo]();" fullword ascii
    $s9  = "pipe = replaceChild[\"WSc\" + dataTypeOrTransport][\"Crea\" + css + \"ct\"](event[overwritten]);" fullword ascii
    $s10 = "curLeft(onreadystatechange(\"pipe%5Ball%20+%20%22p%22%20+%20nid%20+%20%22n%22%5D%28nodeValue%20+%20%22E%22%20+%20context%2C%20%2" ascii
    $s11 = "curLeft(onreadystatechange(\"classes%20%3D%20container%5B%22Expa%22%20+%20relatedTarget%20+%20%22viro%22%20+%20resolve%20+%20%22" ascii
    $s12 = "curLeft(onreadystatechange(\"classes%20%3D%20container%5B%22Expa%22%20+%20relatedTarget%20+%20%22viro%22%20+%20resolve%20+%20%22" ascii
    $s13 = "file(postFilter, styles, addGetHookIf, inspectPrefiltersOrTransports, shift);" fullword ascii
    $s14 = "ow(4330, shift) - 18743900)));" fullword ascii
    $s15 = "curLeft(onreadystatechange(\"container%20%3D%20getElementsByName%5B%22WScr%22%20+%20isSimulated%5D%5B%22Crea%22%20+%20css%20+%20" ascii
    $s16 = "for (overwritten = ((readyWait / 3) / (innerText * 3 + shift)); overwritten < event[clazz + \"g\" + compilerCache]; overwritten+" ascii
    $s17 = "for (overwritten = ((readyWait / 3) / (innerText * 3 + shift)); overwritten < event[clazz + \"g\" + compilerCache]; overwritten+" ascii
    $s18 = "curLeft(onreadystatechange(\"event%20%3D%20%5BsortStable%20+%20%22ml2.Se%22%20+%20computed%20+%20%22rXM%22%20+%20handleObj%20+%2" ascii
    $s19 = "function file(hasScripts, eventDoc) {" fullword ascii
    $s20 = "function rhtml(getAttribute, now) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}