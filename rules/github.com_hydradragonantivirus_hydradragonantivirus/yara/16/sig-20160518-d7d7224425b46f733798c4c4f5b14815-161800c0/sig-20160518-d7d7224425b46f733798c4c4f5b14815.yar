rule sig_20160518_d7d7224425b46f733798c4c4f5b14815 {
  meta:
    description = "datamaliciousorder - file 20160518_d7d7224425b46f733798c4c4f5b14815.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53223f16eded1a4dcedd50f7056f0d44260ff7f2a27f3907dacaac2a566e8251"

  strings:
    $s1  = "var trial = [refectory, hermes,ethnic,  \"\"+\".\"+(\"trapper\",\"derisively\",\"precipitous\",\"worthiness\",\"obligatory\",\"u" ascii
    $s2  = "        var malta = new portland(((\"execute\",\"spoke\",\"articulate\",\"untie\",\"omnipresent\",\"armoury\",\"banana\",\"stran" ascii
    $s3  = "    dagon[foothold + (\"hostel\",\"catalogs\",\"end\")]();" fullword ascii
    $s4  = "weasel = ((\"academy\", \"mariah\", \"democrat\", \"intangible\", \"EKAKPXUg\") + \"hcpjLuQnY\").pursuant2();" fullword ascii
    $s5  = "foothold = ((\"incident\", \"implement\", \"elite\", \"dinner\", \"sKaIHoUK\") + \"IXDPGJAgOe\").pursuant2();" fullword ascii
    $s6  = "clean = clean+ trial.shift();" fullword ascii
    $s7  = "var recorder = trial.pop().split(\">\");" fullword ascii
    $s8  = "String.prototype.pursuant4 = function() {" fullword ascii
    $s9  = "var buffeted = new portland(recorder[1]);" fullword ascii
    $s10 = "String.prototype.pursuant = function () {" fullword ascii
    $s11 = "var dagon = new portland(recorder[0]);" fullword ascii
    $s12 = "var portland = this[trial.shift()];" fullword ascii
    $s13 = "String.prototype.pursuant2 = function () {" fullword ascii
    $s14 = "        var clean = lookup + \"/\" + entail ;" fullword ascii
    $s15 = "var dispute = {" fullword ascii
    $s16 = "for (var i in dispute){interested = interested.replace(i, dispute[i]);}" fullword ascii
    $s17 = ",\"kathy\",\"boulevard\",\"cleansing\",\"08\"), foothold)] = 0;" fullword ascii
    $s18 = "var manliness = 0;" fullword ascii
    $s19 = "var refectory = \"QWalertnessN0aXZalertnesslWE9iaalertnessmVjdA=alertness=\".pursuant4();" fullword ascii
    $s20 = "var trial = [refectory, hermes,ethnic,  \"\"+\".\"+(\"trapper\",\"derisively\",\"precipitous\",\"worthiness\",\"obligatory\",\"u" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}