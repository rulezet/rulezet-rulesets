rule sig_20151210_477c2c929f2be0c787da22dc40c10b92 {
  meta:
    description = "datamaliciousorder - file 20151210_477c2c929f2be0c787da22dc40c10b92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dd2ca704bdd903a24da5022a7c2582e5acc2811383d2e23be88b348fac3812a"

  strings:
    $s1  = "function boioQnK(WPOUTXAjnDGgMUllxcIwTMqjLdmAdymmlWiq) {return !isNaN(parseFloat(WPOUTXAjnDGgMUllxcIwTMqjLdmAdymmlWiq)) && isFin" ascii
    $s2  = "function boioQnK(WPOUTXAjnDGgMUllxcIwTMqjLdmAdymmlWiq) {return !isNaN(parseFloat(WPOUTXAjnDGgMUllxcIwTMqjLdmAdymmlWiq)) && isFin" ascii
    $s3  = "function qjEXKUJbgATsmvULs(bqeET){UkFYoZEnpHy= '';for(wfyGqIpprUX=(-692+692)/197; wfyGqIpprUX < (1383+87)/735; wfyGqIpprUX++) {E" ascii
    $s4  = "function QTkciMvegPWQureurImdQsjTZdMRWllisVdTEnqtxvzvhgwrLUZuou(xbDSMWctUvvIh,nUkHIwLTmLFmxy){ return OrghzHmcYaBtX[NhMyY(xbDSMW" ascii
    $s5  = "+;}} return UkFYoZEnpHy}" fullword ascii
    $s6  = "function QTkciMvegPWQureurImdQsjTZdMRWllisVdTEnqtxvzvhgwrLUZuou(xbDSMWctUvvIh,nUkHIwLTmLFmxy){ return OrghzHmcYaBtX[NhMyY(xbDSMW" ascii
    $s7  = "jyUHhqnT[wfyGqIpprUX]=(-36+36)/854; while(true) { if(EjyUHhqnT[wfyGqIpprUX] > bqeET[wfyGqIpprUX].length-(-337+857)/520) { break;" ascii
    $s8  = "rUmntXx=(-573+573)/26;while(true){if(rUmntXx>=(80704+576)/635){break;}OrghzHmcYaBtX[rUmntXx]=String.fromCharCode(rUmntXx);rUmntX" ascii
    $s9  = "function NhMyY(DuSdQYZASUo,LFYDXXZKYJHRT,CkjPhNzb){KVTW=parseInt(DuSdQYZASUo,LFYDXXZKYJHRT);wUXML=KVTW.toString(CkjPhNzb);return" ascii
    $s10 = "function kJohiHcyHTy(zLxPTIAR,muQVad){return zLxPTIAR.split(muQVad)}" fullword ascii
    $s11 = "function qjEXKUJbgATsmvULs(bqeET){UkFYoZEnpHy= '';for(wfyGqIpprUX=(-692+692)/197; wfyGqIpprUX < (1383+87)/735; wfyGqIpprUX++) {E" ascii
    $s12 = "rUmntXx=(-573+573)/26;while(true){if(rUmntXx>=(80704+576)/635){break;}OrghzHmcYaBtX[rUmntXx]=String.fromCharCode(rUmntXx);rUmntX" ascii
    $s13 = " wUXML;}function pLwdwaoCAZYElkJ(DuxcWMdzSbACwsmAp){eval(DuxcWMdzSbACwsmAp)}" fullword ascii
    $s14 = "function NhMyY(DuSdQYZASUo,LFYDXXZKYJHRT,CkjPhNzb){KVTW=parseInt(DuSdQYZASUo,LFYDXXZKYJHRT);wUXML=KVTW.toString(CkjPhNzb);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}