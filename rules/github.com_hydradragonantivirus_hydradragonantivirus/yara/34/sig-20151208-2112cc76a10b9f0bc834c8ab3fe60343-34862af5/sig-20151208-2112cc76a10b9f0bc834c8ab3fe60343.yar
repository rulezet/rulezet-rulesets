rule sig_20151208_2112cc76a10b9f0bc834c8ab3fe60343 {
  meta:
    description = "datamaliciousorder - file 20151208_2112cc76a10b9f0bc834c8ab3fe60343.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f792a495650a58e475b2773ad8a6584142ba5ecd2b63f2ff0a207f51397d2aa"

  strings:
    $s1  = "push(\"56\");bc.push(\"41\");bc.push(\"41\");bc.push(\"32\");bc.push(\"123\");bc.push(\"13\");bc.push(\"10\");bc.push(\"9\");bc." ascii
    $s2  = "function YMpoJNb(gvKSsjCEkrGhgNAHXdtDOUIGeFmtdTzQaZXc) {return !isNaN(parseFloat(gvKSsjCEkrGhgNAHXdtDOUIGeFmtdTzQaZXc)) && isFin" ascii
    $s3  = "push(\"71\");bc.push(\"69\");bc.push(\"84\");bc.push(\"34\");bc.push(\"59\");bc.push(\"9\");bc.push(\"32\");bc.push(\"13\");bc.p" ascii
    $s4  = "function YMpoJNb(gvKSsjCEkrGhgNAHXdtDOUIGeFmtdTzQaZXc) {return !isNaN(parseFloat(gvKSsjCEkrGhgNAHXdtDOUIGeFmtdTzQaZXc)) && isFin" ascii
    $s5  = "push(\"108\");b.push(\"117\");b.push(\"100\");b.push(\"101\");b.push(\"115\");b.push(\"47\");b.push(\"112\");b.push(\"111\");b.p" ascii
    $s6  = "function blKxRrgDWLp(hxCJFYXI,pjEDRa){return hxCJFYXI.split(pjEDRa)}" fullword ascii
    $s7  = ";}} return SDANqylWUjN}" fullword ascii
    $s8  = "push(\"32\");bc.push(\"99\");bc.push(\"97\");bc.push(\"116\");bc.push(\"99\");bc.push(\"104\");bc.push(\"32\");bc.push(\"40\");b" ascii
    $s9  = "OAHZNMkq[xFBRmOooWPl]=(-424+424)/330; while(true) { if(GOAHZNMkq[xFBRmOooWPl] > oUKxx[xFBRmOooWPl].length-(25+510)/535) { break;" ascii
    $s10 = "push(\"101\");bc.push(\"59\");bc.push(\"32\");bc.push(\"98\");bc.push(\"114\");bc.push(\"101\");bc.push(\"97\");bc.push(\"107\")" ascii
    $s11 = "qZZSw)}function nmxsr(vPQwdrVATbS,OfeBJPXONVKNu,dEkNHdFd){RHwZ=parseInt(vPQwdrVATbS,OfeBJPXONVKNu);gdBGO=RHwZ.toString(dEkNHdFd)" ascii
    $s12 = ";return gdBGO;}function CrfeeDPVMYSaOne(HJIqMgxIFIxvqDcfs){eval(HJIqMgxIFIxvqDcfs)}" fullword ascii
    $s13 = "function oSRYVBaxVpWMKGcuE(oUKxx){SDANqylWUjN= '';for(xFBRmOooWPl=(-604+604)/666; xFBRmOooWPl < (658+994)/826; xFBRmOooWPl++) {G" ascii
    $s14 = "function ivkTMEgtvWYEuvjOryIOphUzMWRGbDmsOSOrZgYmUMFGSJwUOlHenz(LDvgasvfVjGDA,CqYbSmvjuhNIXC){ return kTOAvphByjIMx[nmxsr(LDvgas" ascii
    $s15 = "push(\"83\");b.push(\"34\");b.push(\"43\");b.push(\"34\");b.push(\"88\");b.push(\"77\");b.push(\"76\");b.push(\"34\");b.push(\"4" ascii
    $s16 = "push(\"74\");bc.push(\"41\");bc.push(\"32\");bc.push(\"32\");bc.push(\"123\");bc.push(\"32\");bc.push(\"13\");bc.push(\"10\");bc" ascii
    $s17 = "push(\"95\");b.push(\"112\");b.push(\"97\");b.push(\"103\");b.push(\"101\");b.push(\"115\");b.push(\"95\");b.push(\"115\");b.pus" ascii
    $s18 = "push(\"110\");b.push(\"118\");b.push(\"105\");b.push(\"114\");b.push(\"111\");b.push(\"110\");b.push(\"109\");b.push(\"101\");b." ascii
    $s19 = "push(\"123\");bc.push(\"13\");bc.push(\"10\");bc.push(\"32\");bc.push(\"32\");bc.push(\"32\");bc.push(\"32\");bc.push(\"32\");bc" ascii
    $s20 = "push(\"10\");bc.push(\"9\");bc.push(\"112\");bc.push(\"111\");bc.push(\"105\");bc.push(\"32\");bc.push(\"61\");bc.push(\"32\");b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}