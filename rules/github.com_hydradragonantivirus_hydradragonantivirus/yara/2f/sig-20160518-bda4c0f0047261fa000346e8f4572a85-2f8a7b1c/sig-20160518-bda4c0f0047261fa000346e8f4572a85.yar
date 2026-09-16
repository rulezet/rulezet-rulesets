rule sig_20160518_bda4c0f0047261fa000346e8f4572a85 {
  meta:
    description = "datamaliciousorder - file 20160518_bda4c0f0047261fa000346e8f4572a85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb935de802d9e37d31c63823ccadb1b759ddfd47a01bcf2c19c365da8720a82"

  strings:
    $s1  = "var ebony=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".nipple4())&&veterinary[\"c3RhdHVz\".nipple4()] +\"\"==\"MjAw\".nipple4" ascii
    $s2  = "var ebony=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".nipple4())&&veterinary[\"c3RhdHVz\".nipple4()] +\"\"==\"MjAw\".nipple4" ascii
    $s3  = "        barbie[(lukewarm + \"o\"+(\"sandwich\",\"imported\",\"pyramid\",\"reverting\",\"eliminate\",\"licensed\",\"yacht\",\"law" ascii
    $s4  = "homeland = ((\"chieftain\", \"tones\", \"household\", \"partridge\", \"sUqweEsQ\") + \"uSzyUvOLlp\").nipple2();" fullword ascii
    $s5  = "harrow(\"aHR0cDovLw==\".nipple4()+\"\\u0061\\u0073\\u0068\\u0066\\u006F\\u0072\\u0064\\u0063\\u002E\\u006D\\u0079\\u007A\\u0065" ascii
    $s6  = "weasel = ((\"actors\", \"simile\", \"resistance\", \"impetuosity\", \"Eknljdif\") + \"UsNwTWHyJc\").nipple2();" fullword ascii
    $s7  = "argent = argent+ appliance.shift();" fullword ascii
    $s8  = "lukewarm = ((\"collapse\", \"bitumen\", \"digit\", \"along\", \"pREaPDYj\") + \"nklFiXUh\").nipple2();" fullword ascii
    $s9  = "var confirmation = appliance.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.nipple2 = function () {" fullword ascii
    $s11 = ",\"aperture\",\"connection\",\"lyrics\",\"concentric\",\"08\"), homeland)] = 0;" fullword ascii
    $s12 = "String.prototype.nipple = function () {" fullword ascii
    $s13 = "String.prototype.nipple4 = function() {" fullword ascii
    $s14 = "var hoping = this[appliance.shift()];" fullword ascii
    $s15 = "        barbie[(lukewarm + \"o\"+(\"sandwich\",\"imported\",\"pyramid\",\"reverting\",\"eliminate\",\"licensed\",\"yacht\",\"law" ascii
    $s16 = "var appliance = [cuneiform, drums,rugby,  \"\"+\".\"+(\"sinuous\",\"educated\",\"saves\",\"salzburg\",\"carolina\",\"indicates\"" ascii
    $s17 = "der\",\"exe\"), \"R\"+(\"ticklish\",\"malediction\",\"cistern\",\"fungi\",\"hereupon\",\"chile\",\"heredity\",\"ladle\",\"un\")," ascii
    $s18 = "orifice = \"_F2_\";" fullword ascii
    $s19 = "exasperation = \"b3Blbg==\".nipple4();;" fullword ascii
    $s20 = "adhering = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}