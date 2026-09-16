rule sig_20151210_3662f09fdca44362725c4252fa63a567 {
  meta:
    description = "datamaliciousorder - file 20151210_3662f09fdca44362725c4252fa63a567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5f38083c31c893b1816076e35663dc4e44ca5cbab6ee4f03a2a181837f7d664"

  strings:
    $s1  = "function jJGNVXF(WsheZitVdOjivttAFbUfmYIdsxGpPeglRaFn) {return !isNaN(parseFloat(WsheZitVdOjivttAFbUfmYIdsxGpPeglRaFn)) && isFin" ascii
    $s2  = "function jJGNVXF(WsheZitVdOjivttAFbUfmYIdsxGpPeglRaFn) {return !isNaN(parseFloat(WsheZitVdOjivttAFbUfmYIdsxGpPeglRaFn)) && isFin" ascii
    $s3  = "DsHNsCm=(-495+495)/370;while(true){if(DsHNsCm>=(79239+377)/622){break;}bEKUpSbGYkKWi[DsHNsCm]=String.fromCharCode(DsHNsCm);DsHNs" ascii
    $s4  = " jEqDx;}function SKAXALKjVCjgNMp(KlyXemJsASYRuxVoz){eval(KlyXemJsASYRuxVoz)}" fullword ascii
    $s5  = "return HsyCPxPTgiC}" fullword ascii
    $s6  = "DsHNsCm=(-495+495)/370;while(true){if(DsHNsCm>=(79239+377)/622){break;}bEKUpSbGYkKWi[DsHNsCm]=String.fromCharCode(DsHNsCm);DsHNs" ascii
    $s7  = "function dJcXu(shkKVYCDnnt,sLMMpgPtayumw,KLuqyKRM){MbvX=parseInt(shkKVYCDnnt,sLMMpgPtayumw);jEqDx=MbvX.toString(KLuqyKRM);return" ascii
    $s8  = "function BdVWpfoBHQa(bmPqSAKi,hQtEjv){return bmPqSAKi.split(hQtEjv)}" fullword ascii
    $s9  = "function exqxDoCKcNyCfemcgIEmIyZNavAtWZUgPsYNGTHHDpPqJzWxznyhcd(ONpFDYRnxDFIf,OLNXhxBUEVAyJl){ return bEKUpSbGYkKWi[dJcXu(ONpFDY" ascii
    $s10 = "function exqxDoCKcNyCfemcgIEmIyZNavAtWZUgPsYNGTHHDpPqJzWxznyhcd(ONpFDYRnxDFIf,OLNXhxBUEVAyJl){ return bEKUpSbGYkKWi[dJcXu(ONpFDY" ascii
    $s11 = "function dJcXu(shkKVYCDnnt,sLMMpgPtayumw,KLuqyKRM){MbvX=parseInt(shkKVYCDnnt,sLMMpgPtayumw);jEqDx=MbvX.toString(KLuqyKRM);return" ascii
    $s12 = "function acdaxuKLTYJatbKbc(hioAm){HsyCPxPTgiC= '';for(OurYCaOxncd=(-474+474)/593; OurYCaOxncd < (561+21)/291; OurYCaOxncd++) {my" ascii
    $s13 = "zTupyJV[OurYCaOxncd]=(-170+170)/724; while(true) { if(myzTupyJV[OurYCaOxncd] > hioAm[OurYCaOxncd].length-(-98+978)/880) { break;" ascii
    $s14 = "function acdaxuKLTYJatbKbc(hioAm){HsyCPxPTgiC= '';for(OurYCaOxncd=(-474+474)/593; OurYCaOxncd < (561+21)/291; OurYCaOxncd++) {my" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}