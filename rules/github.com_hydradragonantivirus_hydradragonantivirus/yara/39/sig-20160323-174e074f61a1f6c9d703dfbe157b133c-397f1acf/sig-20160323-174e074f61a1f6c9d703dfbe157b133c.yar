rule sig_20160323_174e074f61a1f6c9d703dfbe157b133c {
  meta:
    description = "datamaliciousorder - file 20160323_174e074f61a1f6c9d703dfbe157b133c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fe14840b1b382cd8f88ffb79c060d1070bd30b05938fef4793602259ecd6771"

  strings:
    $s1  = "return WScript.CreateObject(EpoIs);" fullword ascii
    $s2  = "var UC = true  , JWZD = cNI[7] + cNI[9] + cNI[11];" fullword ascii
    $s3  = "return GTlYBuX[0] + GTlYBuX[2] + GTlYBuX[4] + \".F\" + GTlYBuX[7] + GTlYBuX[9] + GTlYBuX[12] + GTlYBuX[14];" fullword ascii
    $s4  = "var cNI = (\"2.XMLHTTP xMiydFS tiIux XML ream St gqjtOnAH AD cGrOLTN O EyNl D\").split(\" \");" fullword ascii
    $s5  = "var GTlYBuX = zQeLZ(ImkmUFhbXS+\" \"+\"System sQ xrKbH Obj QsVmaH ect NYrXyTc TqdCJ\", \" \");" fullword ascii
    $s6  = "JNgD.open(TYJEb,UUBNb,false);" fullword ascii
    $s7  = "if(r>=Q.length) {break;}" fullword ascii
    $s8  = "return SuUgp.status;" fullword ascii
    $s9  = "return Xla.size;" fullword ascii
    $s10 = "if (GkcBr > 154831-585){return true;} else {return false;}" fullword ascii
    $s11 = "function zQeLZ(MuL,lrrxd) {" fullword ascii
    $s12 = "function FhmaFjyIi(jOWuH) {" fullword ascii
    $s13 = "return BdNSlkg(YC,EhODO[998-992]+EhODO[711-704]+EhODO[411-403]);" fullword ascii
    $s14 = "function zDRB(vbydp,MYttP) {" fullword ascii
    $s15 = "return qPMsa;" fullword ascii
    $s16 = "function EhIM(EpoIs) {" fullword ascii
    $s17 = "function cmPJpkZ(DdcO) {" fullword ascii
    $s18 = "function BLkE(JYQxJ,UUBNb,TYJEb) {" fullword ascii
    $s19 = "if (N >= FCkFH.length) {break;}" fullword ascii
    $s20 = "function ZqrzpJWX(Xla) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}