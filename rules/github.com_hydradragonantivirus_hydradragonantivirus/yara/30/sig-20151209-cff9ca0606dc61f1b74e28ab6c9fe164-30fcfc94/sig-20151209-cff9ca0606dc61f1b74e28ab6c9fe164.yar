rule sig_20151209_cff9ca0606dc61f1b74e28ab6c9fe164 {
  meta:
    description = "datamaliciousorder - file 20151209_cff9ca0606dc61f1b74e28ab6c9fe164.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90c774b393108dbb072abe7fe2f98f52cdda043bb7a90a7146a329d438dd7eab"

  strings:
    $s1  = "function RHVGbgP(xBxfalrWCqNGejGBzAbFYzOAOWqfQxIjintw) {return !isNaN(parseFloat(xBxfalrWCqNGejGBzAbFYzOAOWqfQxIjintw)) && isFin" ascii
    $s2  = "function RHVGbgP(xBxfalrWCqNGejGBzAbFYzOAOWqfQxIjintw) {return !isNaN(parseFloat(xBxfalrWCqNGejGBzAbFYzOAOWqfQxIjintw)) && isFin" ascii
    $s3  = "AhwrZGNr[TIqUsiCcsIB]=(-855+855)/539; while(true) { if(WAhwrZGNr[TIqUsiCcsIB] > EABDO[TIqUsiCcsIB].length-(-382+845)/463) { brea" ascii
    $s4  = "function JHdsTcrudoiuQgQEodHRjLfdAblEPebvvXTRwFgaZfCHwYkNKPTHVv(PHIKlKGrfVcVd,NDmludrfYkHNho){ return VUMDH[NWxiR(PHIKlKGrfVcVd[" ascii
    $s5  = "function NhwiGqFmqVOpYXkuG(EABDO){qgGZrAfSxmB= '';for(TIqUsiCcsIB=(-311+311)/579; TIqUsiCcsIB < (973+541)/757; TIqUsiCcsIB++) {W" ascii
    $s6  = "} return qgGZrAfSxmB}" fullword ascii
    $s7  = "function iScDcguQuPj(KXZyehZt,vIVkSk){return KXZyehZt.split(vIVkSk)}" fullword ascii
    $s8  = "function NWxiR(yPtGYeFhqvl,uFoZcXpjzEBSG,cQAngEri){etMw=parseInt(yPtGYeFhqvl,uFoZcXpjzEBSG);tXilW=etMw.toString(cQAngEri);return" ascii
    $s9  = "function JHdsTcrudoiuQgQEodHRjLfdAblEPebvvXTRwFgaZfCHwYkNKPTHVv(PHIKlKGrfVcVd,NDmludrfYkHNho){ return VUMDH[NWxiR(PHIKlKGrfVcVd[" ascii
    $s10 = "function NhwiGqFmqVOpYXkuG(EABDO){qgGZrAfSxmB= '';for(TIqUsiCcsIB=(-311+311)/579; TIqUsiCcsIB < (973+541)/757; TIqUsiCcsIB++) {W" ascii
    $s11 = " tXilW;}function ccAnsjGHdEnzPDu(QEjqphXHSiTUdTkCY){eval(QEjqphXHSiTUdTkCY)}" fullword ascii
    $s12 = "function NWxiR(yPtGYeFhqvl,uFoZcXpjzEBSG,cQAngEri){etMw=parseInt(yPtGYeFhqvl,uFoZcXpjzEBSG);tXilW=etMw.toString(cQAngEri);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}