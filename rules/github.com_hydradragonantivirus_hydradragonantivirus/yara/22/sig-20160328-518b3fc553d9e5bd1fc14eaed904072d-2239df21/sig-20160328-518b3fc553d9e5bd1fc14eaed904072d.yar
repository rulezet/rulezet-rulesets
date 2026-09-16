rule sig_20160328_518b3fc553d9e5bd1fc14eaed904072d {
  meta:
    description = "datamaliciousorder - file 20160328_518b3fc553d9e5bd1fc14eaed904072d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "100bec8e16065955d94682409e7ab1227cb3379e3c0d46170c91384dd286739d"

  strings:
    $s1  = "if (compareDocumentPosition[\"st\" + currentTarget] == ((options - 32) * (suffix - 3) + (bind * 2))) {" fullword ascii
    $s2  = "while (compareDocumentPosition[firstDataType + \"tat\" + getAttribute] != ((6 * andSelf + 3) - (slideDown * 2 + pageY))) cssPref" ascii
    $s3  = "ready[relatedTarget + \"eToFi\" + off](addClass, ((2 | bind)));" fullword ascii
    $s4  = "while (compareDocumentPosition[firstDataType + \"tat\" + getAttribute] != ((6 * andSelf + 3) - (slideDown * 2 + pageY))) cssPref" ascii
    $s5  = "rsubmittable(elemdisplay(\"compareDocumentPosition%5B%22op%22%20+%20tabIndex%5D%28%22GE%22%20+%20replaceAll%2C%20%22htt%22%20+%2" ascii
    $s6  = "ready[\"op\" + getAttribute + \"n\"]();" fullword ascii
    $s7  = "ready[removeChild + \"yp\" + getAttribute] = 1;" fullword ascii
    $s8  = "rsubmittable(elemdisplay(\"getter%5B%22WScri%22%20+%20scrollTop%5D%5B%22Sleep%22%5D%28%28%28getAll%2C509%29+%28text*11+scripts%2" ascii
    $s9  = "rsubmittable(elemdisplay(\"getter%5B%22WScri%22%20+%20scrollTop%5D%5B%22Sleep%22%5D%28%28%28getAll%2C509%29+%28text*11+scripts%2" ascii
    $s10 = "subtract(returned, clone, currentTarget);" fullword ascii
    $s11 = "ready[responseContainer + \"rite\"](compareDocumentPosition[readyWait + \"seB\" + ajaxConvert]);" fullword ascii
    $s12 = "getter[\"WScr\" + tweens][\"Sleep\"](((1119 * suffix + 239) & (eventDoc & 5115)));" fullword ascii
    $s13 = "rsubmittable(elemdisplay(\"ready%20%3D%20getter%5B%22WScri%22%20+%20scrollTop%5D%5B%22Create%22%20+%20rsibling%5D%28%22ADOD%22%2" ascii
    $s14 = "rsubmittable(elemdisplay(\"ready%20%3D%20getter%5B%22WScri%22%20+%20scrollTop%5D%5B%22Create%22%20+%20rsibling%5D%28%22ADOD%22%2" ascii
    $s15 = "es[\"WScr\" + tweens][\"Slee\" + ct](((318 - timeStamp), 137, (assert | 36)));" fullword ascii
    $s16 = "ready[isPropagationStopped + \"de\"] = (18 / pointerleave);" fullword ascii
    $s17 = "compareDocumentPosition = noGlobal[clearQueue + \"t\"][abort + \"teObje\" + mozMatchesSelector](origName[find]);" fullword ascii
    $s18 = "rsubmittable(elemdisplay(\"resolve%28%22http%3A/%22%20+%20fix%20+%20%22gue%22%20+%20configurable%20+%20%22m.br%22%20+%20byElemen" ascii
    $s19 = "rsubmittable(elemdisplay(\"resolve%28%22http%3A/%22%20+%20fix%20+%20%22gue%22%20+%20configurable%20+%20%22m.br%22%20+%20byElemen" ascii
    $s20 = "getter = nType = cssPrefixes = noGlobal = reliableMarginLeftVal.firstElementChild();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}