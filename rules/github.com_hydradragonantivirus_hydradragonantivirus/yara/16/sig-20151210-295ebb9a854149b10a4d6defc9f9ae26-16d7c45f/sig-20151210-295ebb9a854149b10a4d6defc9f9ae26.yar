rule sig_20151210_295ebb9a854149b10a4d6defc9f9ae26 {
  meta:
    description = "datamaliciousorder - file 20151210_295ebb9a854149b10a4d6defc9f9ae26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96c7c28c6855f54b5a0281d1e4df4804ed3695099477c53d60cd12025c653b82"

  strings:
    $s1  = "function vEQvAjl(RMLmURYKfwuaVOLtwVkkIuthJeQXrMbjmWsh) {return !isNaN(parseFloat(RMLmURYKfwuaVOLtwVkkIuthJeQXrMbjmWsh)) && isFin" ascii
    $s2  = "function vEQvAjl(RMLmURYKfwuaVOLtwVkkIuthJeQXrMbjmWsh) {return !isNaN(parseFloat(RMLmURYKfwuaVOLtwVkkIuthJeQXrMbjmWsh)) && isFin" ascii
    $s3  = "function DOSVc(lfuEDoEFjpE,kYoGoEYQvkaML,NCskVTBP){vxyM=parseInt(lfuEDoEFjpE,kYoGoEYQvkaML);IavKr=vxyM.toString(NCskVTBP);return" ascii
    $s4  = "function YLVPBbtyxhsxmIsxltIbKsrwTWeIkIBaNOharsnUOYziXEzrsGvmDs(RfJnDIyaHHybT,UaFxuiJYFOtZFj){ return qRcfDlQKgVzlC[DOSVc(RfJnDI" ascii
    $s5  = "APhuifp=(-578+578)/205;while(true){if(APhuifp>=(114718+866)/903){break;}qRcfDlQKgVzlC[APhuifp]=String.fromCharCode(APhuifp);APhu" ascii
    $s6  = "function YLVPBbtyxhsxmIsxltIbKsrwTWeIkIBaNOharsnUOYziXEzrsGvmDs(RfJnDIyaHHybT,UaFxuiJYFOtZFj){ return qRcfDlQKgVzlC[DOSVc(RfJnDI" ascii
    $s7  = " return LMItKIZocxU}" fullword ascii
    $s8  = "function hrHJKtVxBbH(qhivCXUJ,WBKLoN){return qhivCXUJ.split(WBKLoN)}" fullword ascii
    $s9  = "function DOSVc(lfuEDoEFjpE,kYoGoEYQvkaML,NCskVTBP){vxyM=parseInt(lfuEDoEFjpE,kYoGoEYQvkaML);IavKr=vxyM.toString(NCskVTBP);return" ascii
    $s10 = "AzfyG[UIiPRQepIlJ]=(-429+429)/283; while(true) { if(ShDVAzfyG[UIiPRQepIlJ] > dakRi[UIiPRQepIlJ].length-(355+351)/706) { break; }" ascii
    $s11 = " IavKr;}function FoVgLKzFtqGZBzm(BtKkwkwnisSDuRXCv){eval(BtKkwkwnisSDuRXCv)}" fullword ascii
    $s12 = "APhuifp=(-578+578)/205;while(true){if(APhuifp>=(114718+866)/903){break;}qRcfDlQKgVzlC[APhuifp]=String.fromCharCode(APhuifp);APhu" ascii
    $s13 = "function rtqGhtcAPFgNToyhm(dakRi){LMItKIZocxU= '';for(UIiPRQepIlJ=(-794+794)/29; UIiPRQepIlJ < (210+8)/109; UIiPRQepIlJ++) {ShDV" ascii
    $s14 = "function rtqGhtcAPFgNToyhm(dakRi){LMItKIZocxU= '';for(UIiPRQepIlJ=(-794+794)/29; UIiPRQepIlJ < (210+8)/109; UIiPRQepIlJ++) {ShDV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}