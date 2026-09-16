rule sig_20160311_46a494e5eb1278ed1b7b03385542229c {
  meta:
    description = "datamaliciousorder - file 20160311_46a494e5eb1278ed1b7b03385542229c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "863b51b25faca27f311d4867d904cb864f566d9ddf247680cb3e5e61760ad03a"

  strings:
    $s1  = "function EFtP(cfcIv) {" fullword ascii
    $s2  = "var VZ = true  , KZQF = Doz[7] + Doz[9] + Doz[11];" fullword ascii
    $s3  = "return Jctlweg[0] + Jctlweg[2] + Jctlweg[4] + \".F\" + Jctlweg[7] + Jctlweg[9] + Jctlweg[12] + Jctlweg[14];" fullword ascii
    $s4  = "IQgpG.open(utQeQ,rPfZZ,false);" fullword ascii
    $s5  = "var Doz = (\"2.XMLHTTP BWsIOqP HXFVM XML ream St fJMwBZmz AD BdQUZyT O XYzD D\").split(\" \");" fullword ascii
    $s6  = "VkH = j; break; " fullword ascii
    $s7  = "return jRAkAIE" fullword ascii
    $s8  = "if (ApqJv > 127616-771){return true;} else {return false;}" fullword ascii
    $s9  = "if (c >= MNStl.length) {break;}" fullword ascii
    $s10 = "return uhSzP.status;" fullword ascii
    $s11 = "function bsgsoGbA() {" fullword ascii
    $s12 = "function XikW(amPRL,nNszb) {" fullword ascii
    $s13 = "function JObyKFMqP(NVqdMXYskYz) {" fullword ascii
    $s14 = "if(j>=C.length) {break;}" fullword ascii
    $s15 = "if (MARJq == 802-602){return true;} else {return false;}" fullword ascii
    $s16 = "function HCbqOxIJ(fwlrX,yBTxQd) {" fullword ascii
    $s17 = "function wfgGYgBT(eJM) {" fullword ascii
    $s18 = "function ITQIwWB(wbyr,kJgix) {" fullword ascii
    $s19 = "function BNCBWjcgU() {" fullword ascii
    $s20 = "return eJM.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}