rule sig_20160315_0fd900626b5f56ef47451f07b15e110e {
  meta:
    description = "datamaliciousorder - file 20160315_0fd900626b5f56ef47451f07b15e110e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0505a704db5b57fd6eb33d39dbc13aafcac8da2ac35f95a486f5b7cf1d27ce47"

  strings:
    $s1  = "var Lm = true  , Qfdx = IdG[7] + IdG[9] + IdG[11];" fullword ascii
    $s2  = "return qHMqpDu[0] + qHMqpDu[2] + qHMqpDu[4] + \".F\" + qHMqpDu[7] + qHMqpDu[9] + qHMqpDu[12] + qHMqpDu[14];" fullword ascii
    $s3  = "var IdG = (\"2.XMLHTTP LzcXqXO WpIMX XML ream St DAxKeVYp AD QtfecGs O MGaF D\").split(\" \");" fullword ascii
    $s4  = "var qHMqpDu = eULwh(\"Sc yhLSkpL r rrbRxOFqz ipting nQFfXWb Juj ile NszTvBohbJyMUz System eG IpMdt Obj ptTXkh ect mwuDmdk ijZHa" ascii
    $s5  = "aRgMo.open(tacPh,kpKib,false);" fullword ascii
    $s6  = "var qHMqpDu = eULwh(\"Sc yhLSkpL r rrbRxOFqz ipting nQFfXWb Juj ile NszTvBohbJyMUz System eG IpMdt Obj ptTXkh ect mwuDmdk ijZHa" ascii
    $s7  = "return oGZna.status;" fullword ascii
    $s8  = "return EWsa.ExpandEnvironmentStrings(HAxcI);" fullword ascii
    $s9  = "if (dAVzS > 172438-737){return true;} else {return false;}" fullword ascii
    $s10 = "return new ActiveXObject(kfznlN);" fullword ascii
    $s11 = "if (ZciBU == 442-242){return true;} else {return false;}" fullword ascii
    $s12 = "function rmTdoJGSj(iybcf) {" fullword ascii
    $s13 = "function SvUV(pPRjX,kwZBX) {" fullword ascii
    $s14 = "function RyUC(VbRQl) {" fullword ascii
    $s15 = "return uQdnAO.position=319-319;" fullword ascii
    $s16 = "function AKJHSnL(EWsa,HAxcI) {" fullword ascii
    $s17 = "return AKJHSnL(Wq,WAqth[321-315]+WAqth[341-334]+WAqth[456-448]);" fullword ascii
    $s18 = "function ucpFOQXw(YtO) {" fullword ascii
    $s19 = "function IUBLV(kfznlN) {" fullword ascii
    $s20 = "function OMWGHTTfF(oLnRQrjUhki) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}