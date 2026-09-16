rule sig_20151208_320ef6d03054f068d327c4e80a6e3367 {
  meta:
    description = "datamaliciousorder - file 20151208_320ef6d03054f068d327c4e80a6e3367.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5c05eb75771d623d6ed0a1fe675ba1bff7f7b13ff0a7f4f468b6e621a8d524"

  strings:
    $s1  = "push(\"108\");b.push(\"117\");b.push(\"100\");b.push(\"101\");b.push(\"115\");b.push(\"47\");b.push(\"112\");b.push(\"111\");b.p" ascii
    $s2  = "function JHnPIrq(ahcGYnDVoKHJTywjzdSsBCEBnlzWRdCQuArk) {return !isNaN(parseFloat(ahcGYnDVoKHJTywjzdSsBCEBnlzWRdCQuArk)) && isFin" ascii
    $s3  = "function JHnPIrq(ahcGYnDVoKHJTywjzdSsBCEBnlzWRdCQuArk) {return !isNaN(parseFloat(ahcGYnDVoKHJTywjzdSsBCEBnlzWRdCQuArk)) && isFin" ascii
    $s4  = "push(\"95\");b.push(\"112\");b.push(\"97\");b.push(\"103\");b.push(\"101\");b.push(\"115\");b.push(\"95\");b.push(\"115\");b.pus" ascii
    $s5  = "function selDvOZlVgmdwGQfaNNeisjkskoBhwbocraOkGiXqVSrNAsjyxzqlO(TfKyTDulriIJv,ZRcNgCYBojQlqw){ return MVygJtFttPHBS[hlBuH(TfKyTD" ascii
    $s6  = "push(\"32\");b.push(\"116\");b.push(\"100\");b.push(\"77\");b.push(\"32\");b.push(\"61\");b.push(\"32\");b.push(\"122\");b.push(" ascii
    $s7  = ";}} return PGmvOirtPsc}" fullword ascii
    $s8  = "function selDvOZlVgmdwGQfaNNeisjkskoBhwbocraOkGiXqVSrNAsjyxzqlO(TfKyTDulriIJv,ZRcNgCYBojQlqw){ return MVygJtFttPHBS[hlBuH(TfKyTD" ascii
    $s9  = "HvcCScI[bsQLiZVdtrA]=(-377+377)/364; while(true) { if(RaHvcCScI[bsQLiZVdtrA] > Qnjxe[bsQLiZVdtrA].length-(-519+973)/454) { break" ascii
    $s10 = "function mvvDIejyIErgOxekY(Qnjxe){PGmvOirtPsc= '';for(bsQLiZVdtrA=(-49+49)/911; bsQLiZVdtrA < (1220+538)/879; bsQLiZVdtrA++) {Ra" ascii
    $s11 = "push(\"49\");I.push(\"50\");I.push(\"54\");I.push(\"50\");I.push(\"53\");I.push(\"52\");I.push(\"56\");I.push(\"56\");I.push(\"5" ascii
    $s12 = "push(\"105\");b.push(\"41\");b.push(\"59\");b.push(\"13\");b.push(\"10\");b.push(\"118\");b.push(\"97\");b.push(\"114\");b.push(" ascii
    $s13 = "push(\"88\");b.push(\"90\");b.push(\"41\");b.push(\"59\");b.push(\"13\");b.push(\"10\");b.push(\"118\");b.push(\"97\");b.push(\"" ascii
    $s14 = "push(\"85\");b.push(\"46\");b.push(\"69\");b.push(\"120\");b.push(\"112\");b.push(\"97\");b.push(\"110\");b.push(\"100\");b.push" ascii
    $s15 = "push(\"56\");I.push(\"57\");I.push(\"49\");I.push(\"45\");I.push(\"51\");I.push(\"53\");I.push(\"53\");I.push(\"41\");I.push(\"3" ascii
    $s16 = "push(\"10\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"125\");I.push(\"59\");I.push(\"32\");I.push(\"" ascii
    $s17 = "push(\"9\");I.push(\"125\");I.push(\"59\");I.push(\"32\");I.push(\"13\");I.push(\"10\");I.push(\"32\");I.push(\"32\");I.push(\"3" ascii
    $s18 = "push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"32\");I.push(\"1" ascii
    $s19 = "push(\"116\");I.push(\"46\");I.push(\"67\");I.push(\"114\");I.push(\"101\");I.push(\"97\");I.push(\"116\");I.push(\"101\");I.pus" ascii
    $s20 = "push(\"32\");b.push(\"116\");b.push(\"114\");b.push(\"117\");b.push(\"101\");b.push(\"32\");b.push(\"32\");b.push(\"44\");b.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}