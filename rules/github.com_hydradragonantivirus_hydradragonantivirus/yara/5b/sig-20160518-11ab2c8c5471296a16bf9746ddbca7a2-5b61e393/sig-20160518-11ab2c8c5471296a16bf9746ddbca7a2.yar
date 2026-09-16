rule sig_20160518_11ab2c8c5471296a16bf9746ddbca7a2 {
  meta:
    description = "datamaliciousorder - file 20160518_11ab2c8c5471296a16bf9746ddbca7a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "306a153054ae1c95ac1bc410831be20bdb22a777daabd63a9ba7bbd1ab2b1e2e"

  strings:
    $s1  = "var infringement = [objective, tiara,manchu,  \"\"+\".\"+(\"inquiry\",\"effie\",\"helpfulness\",\"wales\",\"ministers\",\"films" ascii
    $s2  = "evacuation = ((\"offender\", \"american\", \"unmarked\", \"logitech\", \"sMBdXMYvPAQF\") + \"sqjdTye\").unchanging2();" fullword ascii
    $s3  = "        var legion = new digit(((\"menial\",\"improved\",\"furze\",\"fiftyfour\",\"transcript\",\"shorten\",\"ursula\",\"wizard" ascii
    $s4  = "superior(\"aHR0cDovLw==\".unchanging4()+\"\\u0072\\u006F\\u0074\\u0073\\u0069\\u006E\\u006F\\u006C\\u0069\\u002E\"+\"\\u0072\\u0" ascii
    $s5  = "weasel = ((\"dirge\", \"pheasant\", \"plover\", \"characterization\", \"EcgisIITQQ\") + \"YilDnIOoFDR\").unchanging2();" fullword ascii
    $s6  = "inauguration = inauguration+ infringement.shift();" fullword ascii
    $s7  = "String.prototype.unchanging4 = function() {" fullword ascii
    $s8  = "var picked = infringement.pop().split(\">\");" fullword ascii
    $s9  = "String.prototype.unchanging2 = function () {" fullword ascii
    $s10 = "String.prototype.unchanging = function () {" fullword ascii
    $s11 = "        legion[(cells + \"o\"+(\"edwards\",\"crackers\",\"discrimination\",\"portrayal\",\"context\",\"example\",\"artists\",\"d" ascii
    $s12 = "    afghanistan[evacuation + (\"combining\",\"advice\",\"end\")]();" fullword ascii
    $s13 = "        var legion = new digit(((\"menial\",\"improved\",\"furze\",\"fiftyfour\",\"transcript\",\"shorten\",\"ursula\",\"wizard" ascii
    $s14 = "les, false);" fullword ascii
    $s15 = "var tiara =\"RXhwYW5undefiledkRW52aXundefiledJvbm1lbnRTdHJundefiledpbmdz\".unchanging4();" fullword ascii
    $s16 = "var infringement = [objective, tiara,manchu,  \"\"+\".\"+(\"inquiry\",\"effie\",\"helpfulness\",\"wales\",\"ministers\",\"films" ascii
    $s17 = "var reappearance = czech[infringement.shift()](infringement.shift());" fullword ascii
    $s18 = "var afghanistan = new digit(picked[0]);" fullword ascii
    $s19 = "+\"ML\"+(\"needs\",\"revenues\",\"winds\",\"glimmering\",\"soever\",\"sixtyeight\",\"laptops\",\"2.\")+\"|M\"+\"LH\"+\"TT\"+(\"i" ascii
    $s20 = "var czech = new digit(picked[1]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}