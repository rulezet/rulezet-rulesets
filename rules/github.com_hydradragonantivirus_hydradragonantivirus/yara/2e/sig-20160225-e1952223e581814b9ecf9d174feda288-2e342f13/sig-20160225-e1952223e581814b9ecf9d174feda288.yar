rule sig_20160225_e1952223e581814b9ecf9d174feda288 {
  meta:
    description = "datamaliciousorder - file 20160225_e1952223e581814b9ecf9d174feda288.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ff651dc8572c5e9fc050cb61d36ec448a5ead1ff1d7c0fbcb3993c9c84c98e6"

  strings:
    $s1  = "69\\u006c\\u0061n.\\u0063\" + \"\\u006fm/bl\" + \"og\" + \"\\u002fwp\" + \"-i\" + \"nc\\u006cude\" + \"\\u0073\\u002flo\\u0067\"" ascii
    $s2  = "function String.prototype.photographDialogue(a) {return this;} " fullword ascii
    $s3  = "    angelExtreme = this[\"WS\" + \"crip\\u0074\"][\"\\u0043r\\u0065\" + \"ateO\\u0062j\" + \"\\u0065c\\u0074\"](\"M\\u0053\\u005" ascii
    $s4  = "    angelExtreme = this[\"WS\" + \"crip\\u0074\"][\"\\u0043r\\u0065\" + \"ateO\\u0062j\" + \"\\u0065c\\u0074\"](\"M\\u0053\\u005" ascii
    $s5  = "    while (angelExtreme[\"r\\u0065\" + \"\\u0061\\u0064\\u0079s\\u0074\\u0061\" + \"t\\u0065\"] < ((120/30)&2*3)) {" fullword ascii
    $s6  = "    productFragment = this[\"\\u0057\\u0053cr\\u0069p\" + \"\\u0074\"][\"C\" + \"reat\\u0065\\u004f\" + \"bj\\u0065c\" + \"\\u00" ascii
    $s7  = "    productFragment = this[\"\\u0057\\u0053cr\\u0069p\" + \"\\u0074\"][\"C\" + \"reat\\u0065\\u004f\" + \"bj\\u0065c\" + \"\\u00" ascii
    $s8  = "        this[\"W\\u0053\\u0063rip\" + \"t\"][\"\\u0053l\\u0065\\u0065\\u0070\"](((19+52)+((((([!+[]+!+[]]))+\"\"+(([!+[]+!+[]+!+" ascii
    $s9  = "    parkContrast = this[\"\\u0057\\u0053\\u0063\\u0072ip\" + \"\\u0074\"][\"Cr\\u0065\\u0061\\u0074\" + \"\\u0065\\u004fb\\u006a" ascii
    $s10 = "    parkContrast = this[\"\\u0057\\u0053\\u0063\\u0072ip\" + \"\\u0074\"][\"Cr\\u0065\\u0061\\u0074\" + \"\\u0065\\u004fb\\u006a" ascii
    $s11 = "        this[\"W\\u0053\\u0063rip\" + \"t\"][\"\\u0053l\\u0065\\u0065\\u0070\"](((19+52)+((((([!+[]+!+[]]))+\"\"+(([!+[]+!+[]+!+" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}