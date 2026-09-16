rule sig_20160328_2645a5c4a81a06c39453f14d2b9d98bd {
  meta:
    description = "datamaliciousorder - file 20160328_2645a5c4a81a06c39453f14d2b9d98bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f96c72676665f8004e047b516c5841a8d9396bba23b8682ea6db8d7c6af2c88d"

  strings:
    $s1  = "timer(currentTarget, keys, active, dataUser);" fullword ascii
    $s2  = "  for(processData = ((elemData & 1) * wrap); processData < option[ap + \"ength\"]; processData++) {" fullword ascii
    $s3  = "base[\"m\" + keys + \"d\" + hash] = ((3 | matcher) | 1);" fullword ascii
    $s4  = "      w = createOptions[tokenize + \"pt\"][camelCase + \"teO\" + image](option[processData]);" fullword ascii
    $s5  = "  DOMParser(noConflict(\"option%20%3D%20%5BeventPath%20+%20%22ml2.S%22%20+%20fn%20+%20%22XMLHTT%22%20+%20parsed%20+%20%220%22%2C" ascii
    $s6  = "  while(w[propHooks + \"tate\"] != ((doc - 8) * (isDefaultPrevented | 0))) tokenCache[tokenize + \"pt\"][condense](((matcher * 1" ascii
    $s7  = "  while(w[propHooks + \"tate\"] != ((doc - 8) * (isDefaultPrevented | 0))) tokenCache[tokenize + \"pt\"][condense](((matcher * 1" ascii
    $s8  = " (size * 8 + matcher)));" fullword ascii
    $s9  = "  if(w[\"sta\" + hooks] == (200 & (unquoted * 22 + doc))) {" fullword ascii
    $s10 = "base[\"t\" + attributes + \"e\"] = (elemData * 1);" fullword ascii
    $s11 = "function completed(fromCharCode) {" fullword ascii
    $s12 = "    base[\"Writ\" + hash](w[\"respo\" + remaining + \"ody\"]);" fullword ascii
    $s13 = "function timer() {" fullword ascii
    $s14 = "function genFx() {" fullword ascii
    $s15 = "function speeds() {" fullword ascii
    $s16 = "function rattributeQuotes() {" fullword ascii
    $s17 = "function fadeTo() {" fullword ascii
    $s18 = "function opener() {" fullword ascii
    $s19 = "  DOMParser(noConflict(\"base%5BisPropagationStopped%20+%20%22eToFi%22%20+%20preDispatch%5D%28n%2C%20%28%28col*3%29%2C%28active%" ascii
    $s20 = "function responseContainer(rbuggyMatches, parseFromString) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}