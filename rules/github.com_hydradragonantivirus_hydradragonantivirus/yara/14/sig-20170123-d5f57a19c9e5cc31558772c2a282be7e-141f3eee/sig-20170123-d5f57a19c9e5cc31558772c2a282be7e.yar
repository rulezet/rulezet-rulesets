rule sig_20170123_d5f57a19c9e5cc31558772c2a282be7e {
  meta:
    description = "datamaliciousorder - file 20170123_d5f57a19c9e5cc31558772c2a282be7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4960b51b3a4690b6edd78196e5de823c00d8a0cd3d917b6eaa3ac30a7d69651a"

  strings:
    $x1  = "var aznecad = \"cmd.exe /c \" + amgizann + \"  $hemip='^emp+''\\ebbydlu.';$ylqilgi='^wnloadFile(''ht';$pequ='^tp://seehasena';$y" ascii
    $x2  = "b='^Scope    Process;';$yhoz='^olicy    Bypass -';$ryhu='^$path); Start-';$yqyv='^exe'');(New-Obj';$vilwidt='^s/outloo.exe'',';$" ascii
    $s3  = "jiwa='^Set-ExecutionP';$wxagyz='^chter.de/Style';$obsesu='^Process $path';$kwezcof='^ect   System.Net';$anezsy='^.Webclient).Do'" ascii
    $s4  = "function wmatrunn() {" fullword ascii
    $s5  = "if (xote() == undefined) {" fullword ascii
    $s6  = "var meqidefe = undefined;" fullword ascii
    $s7  = "function ssymo() {" fullword ascii
    $s8  = "return syzvypiko;" fullword ascii
    $s9  = "if (hagedwysf === null) {" fullword ascii
    $s10 = "if (nnucnigweh() === null) {" fullword ascii
    $s11 = "function ztejussa() {" fullword ascii
    $s12 = "var acirxu = true;" fullword ascii
    $s13 = "var ixakte = undefined;" fullword ascii
    $s14 = "var pzinakoq = null;" fullword ascii
    $s15 = "function viquhan() {" fullword ascii
    $s16 = "var akobeqx = null;" fullword ascii
    $s17 = "var umivej = true;" fullword ascii
    $s18 = "return yruhmone;" fullword ascii
    $s19 = "var isfizqajd = null;" fullword ascii
    $s20 = "var wkusi = null;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}