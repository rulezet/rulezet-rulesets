rule sig_20151209_3822fc046a3fb9d6d4e5919b1f125273 {
  meta:
    description = "datamaliciousorder - file 20151209_3822fc046a3fb9d6d4e5919b1f125273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b815e80d28369ded2855c5d86e2e4e758a5f771925c990891f26ef2502018df2"

  strings:
    $s1  = "function yXUvaLz(YrEckczCQPflfeWJZxsAUTgFLrQFNoryrJwh) {return !isNaN(parseFloat(YrEckczCQPflfeWJZxsAUTgFLrQFNoryrJwh)) && isFin" ascii
    $s2  = "function yXUvaLz(YrEckczCQPflfeWJZxsAUTgFLrQFNoryrJwh) {return !isNaN(parseFloat(YrEckczCQPflfeWJZxsAUTgFLrQFNoryrJwh)) && isFin" ascii
    $s3  = ";}} return nNUJJvOsqGY}" fullword ascii
    $s4  = "function YSpIS(fOnyMwFAQza,tlXQwvtrZRvFb,SOGAUjBB){AVOB=parseInt(fOnyMwFAQza,tlXQwvtrZRvFb);jaRiU=AVOB.toString(SOGAUjBB);return" ascii
    $s5  = " jaRiU;}function xiJbyGkLxVDGadO(opUNfLBLGryImaSZr){eval(opUNfLBLGryImaSZr)}" fullword ascii
    $s6  = "function ZmFxSEDnvAZdwfbsc(SZwnG){nNUJJvOsqGY= '';for(NSunQHXKlus=(-275+275)/957; NSunQHXKlus < (48+874)/461; NSunQHXKlus++) {QV" ascii
    $s7  = "function ZPgqvxpyhkLoKUgfYPVJsbsWMpNFMRZYUqLDEskqoThLJzDKusXRNn(iwXIZgedcFpnV,MsZfTnPAwFbuqG){ return gSJLw[YSpIS(iwXIZgedcFpnV[" ascii
    $s8  = "function ZPgqvxpyhkLoKUgfYPVJsbsWMpNFMRZYUqLDEskqoThLJzDKusXRNn(iwXIZgedcFpnV,MsZfTnPAwFbuqG){ return gSJLw[YSpIS(iwXIZgedcFpnV[" ascii
    $s9  = "function jYXyaETsdDU(XsREXZuo,xlwHZF){return XsREXZuo.split(xlwHZF)}" fullword ascii
    $s10 = "DJkECbN[NSunQHXKlus]=(-744+744)/668; while(true) { if(QVDJkECbN[NSunQHXKlus] > SZwnG[NSunQHXKlus].length-(-232+573)/341) { break" ascii
    $s11 = "function ZmFxSEDnvAZdwfbsc(SZwnG){nNUJJvOsqGY= '';for(NSunQHXKlus=(-275+275)/957; NSunQHXKlus < (48+874)/461; NSunQHXKlus++) {QV" ascii
    $s12 = "function YSpIS(fOnyMwFAQza,tlXQwvtrZRvFb,SOGAUjBB){AVOB=parseInt(fOnyMwFAQza,tlXQwvtrZRvFb);jaRiU=AVOB.toString(SOGAUjBB);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}