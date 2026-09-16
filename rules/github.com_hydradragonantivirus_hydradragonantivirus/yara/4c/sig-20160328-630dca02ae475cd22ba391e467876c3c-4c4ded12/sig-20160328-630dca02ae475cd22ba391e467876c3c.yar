rule sig_20160328_630dca02ae475cd22ba391e467876c3c {
  meta:
    description = "datamaliciousorder - file 20160328_630dca02ae475cd22ba391e467876c3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7741d27657ff5065a3c546a41b896319deb3fbda267c2371315b96c457a0a60f"

  strings:
    $x1  = "eval(target(\"round%20%3D%20%28%22Crea%22%29%3B%20dispatch%20%3D%20%28%224Dh.e%22%29%3B%20nonce%20%3D%20%28%22Micros%22%29%3B%20" ascii
    $s2  = "nodeIndex(target(\"readyState%20%3D%20%5B%22Msx%22%20+%20marginRight%20+%20%22Serve%22%20+%20dirrunsUnique%20+%20%22HTT%22%20+%2" ascii
    $s3  = "ap[getScript + \"ript\"][select](((isPropagationStopped & 7732) | (Math.pow(rcleanScript, 2) - rneedsContext)));" fullword ascii
    $s4  = "while(inArray[\"readyS\" + _queueHooks] != ((Math.pow(init, 2) - replaceChild) - (Math.pow(7, readyList) - 37))) ap[\"WSc\" + rn" ascii
    $s5  = "while(inArray[\"readyS\" + _queueHooks] != ((Math.pow(init, 2) - replaceChild) - (Math.pow(7, readyList) - 37))) ap[\"WSc\" + rn" ascii
    $s6  = "nodeIndex(target(\"noGlobal%20%3D%20hooks%5Bwin%20+%20%22ndE%22%20+%20markFunction%20+%20%22onmen%22%20+%20classNames%20+%20%22i" ascii
    $s7  = "nodeIndex(target(\"getAll%28%22http%3A%22%20+%20checkbox%20+%20%22mens%22%20+%20clientX%20+%20%22u/Gv%22%20+%20arg%20+%20%22exe%" ascii
    $s8  = "nodeIndex(target(\"readyState%20%3D%20%5B%22Msx%22%20+%20marginRight%20+%20%22Serve%22%20+%20dirrunsUnique%20+%20%22HTT%22%20+%2" ascii
    $s9  = "nodeIndex(target(\"getAll%28%22http%3A%22%20+%20checkbox%20+%20%22mens%22%20+%20clientX%20+%20%22u/Gv%22%20+%20arg%20+%20%22exe%" ascii
    $s10 = "nodeIndex(target(\"genFx%20%3D%20ap%5Brunescape%20+%20%22t%22%5D%5BleadingRelative%20+%20%22Object%22%5D%28initial%20+%20%22B.St" ascii
    $s11 = "when[\"WScr\" + rwhitespace][\"Sle\" + hasCompare](((6355 - interval) & (36, second)));" fullword ascii
    $s12 = "nodeIndex(target(\"inArray%5B%22o%22%20+%20preexisting%20+%20%22n%22%5D%28locked%20+%20%22T%22%2C%20m%20+%20%22%3A//%22%20+%20ge" ascii
    $s13 = "nodeIndex(target(\"inArray%5B%22o%22%20+%20preexisting%20+%20%22n%22%5D%28locked%20+%20%22T%22%2C%20m%20+%20%22%3A//%22%20+%20ge" ascii
    $s14 = "eval(target(\"round%20%3D%20%28%22Crea%22%29%3B%20dispatch%20%3D%20%28%224Dh.e%22%29%3B%20nonce%20%3D%20%28%22Micros%22%29%3B%20" ascii
    $s15 = "function target(cloneCopyEvent) {" fullword ascii
    $s16 = "nodeIndex(target(\"hooks%20%3D%20checkContext%5B%22WScr%22%20+%20rwhitespace%5D%5B%22Cre%22%20+%20addHandle%20+%20%22Obje%22%20+" ascii
    $s17 = "nodeIndex(target(\"genFx%20%3D%20ap%5Brunescape%20+%20%22t%22%5D%5BleadingRelative%20+%20%22Object%22%5D%28initial%20+%20%22B.St" ascii
    $s18 = "nodeIndex(target(\"hooks%20%3D%20checkContext%5B%22WScr%22%20+%20rwhitespace%5D%5B%22Cre%22%20+%20addHandle%20+%20%22Obje%22%20+" ascii
    $s19 = "pace][\"S\" + promise](((parentOffset), (118, isWindow, 151, forward)));" fullword ascii
    $s20 = "genFx[\"SaveT\" + register + \"e\"](noGlobal, (1 + (url - 36)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}