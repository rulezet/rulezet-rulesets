rule sig_20160308_46d923cb6650f1dbba55764d8fc743b9 {
  meta:
    description = "datamaliciousorder - file 20160308_46d923cb6650f1dbba55764d8fc743b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7a92a8ea86cb75fbd30ef9ed854d41dedaa12dac78e62a0af089fe0a4b8798"

  strings:
    $s1  = "return wTfoPso[0] + wTfoPso[2] + wTfoPso[4] + \".F\" + wTfoPso[7] + wTfoPso[9] + wTfoPso[12] + wTfoPso[14];" fullword ascii
    $s2  = "var mU = true  , CsxF = WBX[7] + WBX[9] + WBX[11];" fullword ascii
    $s3  = "onDNQ.open(UryKu,mYPKQ,false);" fullword ascii
    $s4  = "var WBX = (\"2.XMLHTTP zvcxyHZ bdVNY XML ream St UmamRfLx AD EnqxZCU O Wstv D\").split(\" \");" fullword ascii
    $s5  = "var wTfoPso = \"Sc PWRhDKn r BfdgBaDit ipting QywTFDZ dex ile jZKdmsvHwTTcnr System GH WEZAU Obj SkrmRF ect GjoDNck\".split(\" " ascii
    $s6  = "function YAFb(Awdks) {" fullword ascii
    $s7  = "sScZ(BbA); BbA.type = 1; hail(BbA,tSYPzaW(he)); if (YAFb(kfZaQtDE(BbA)))  {" fullword ascii
    $s8  = "function hail(UpjNl,kgziO) {" fullword ascii
    $s9  = "function rOli(onDNQ,mYPKQ,UryKu) {" fullword ascii
    $s10 = "return aG.ExpandEnvironmentStrings(OHcRd[6]+OHcRd[7]+OHcRd[8]);" fullword ascii
    $s11 = "return LZKi.responseBody;" fullword ascii
    $s12 = "function cxVZs(GuZsSR) {" fullword ascii
    $s13 = "if (GcZHz == 518-318){return true;} else {return false;}" fullword ascii
    $s14 = "function sScZ(jSzoM) {" fullword ascii
    $s15 = "function BUzF(YPaqd,yXodD) {" fullword ascii
    $s16 = "function qEZpSoEVB(qxUIE,bWpjM,oPUgh,FaXD) {" fullword ascii
    $s17 = "function AWFH(dxgdr) {" fullword ascii
    $s18 = "function VhfF(uGGBz) {" fullword ascii
    $s19 = "function owRU(DFemE) {" fullword ascii
    $s20 = "function kfZaQtDE(xwC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}