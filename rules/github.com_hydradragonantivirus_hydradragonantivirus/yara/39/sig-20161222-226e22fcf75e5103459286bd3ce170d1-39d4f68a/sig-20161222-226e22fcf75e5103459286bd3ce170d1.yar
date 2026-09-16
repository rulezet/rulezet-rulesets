rule sig_20161222_226e22fcf75e5103459286bd3ce170d1 {
  meta:
    description = "datamaliciousorder - file 20161222_226e22fcf75e5103459286bd3ce170d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dedf48735fa9bcb628d351b1d5f6f2e55d99c4afbf4705d287c21dd7c54e89e9"

  strings:
    $s1  = "96>>0xc));var jipAS7gurcz=this.split(\"\");if (Number(ou35WZlyfC[jipAS7gurcz.length*6-3]) - (~(~(51904512>>0x13))) == ((~(-15704" ascii
    $s2  = "function String.prototype.s(){;var L8Ornk2GTU=(((60293120>>0x12)*(0x35d877c9b02d8400/3879982787107587072)+(224395264>>0x15))%(40" ascii
    $s3  = "while(HOVTkq6_o5==(((~-138)*(134217728>>>26)+(5046272>>>0x10))%(0x20000>>>0x11))){e8RoK5['' + ('PH8', 'tI1B', 'ebquI', 'lcI3u', " ascii
    $s4  = "while(e8RoK5['' + ('svwmw', '6hQ', 'ra9M1', 'ukloE', 'r4Vk0'.s()) + ('4bZ4P', 'RRonE', 'egba'.s()) + ('Ak_', 'yucEU', 'TGlT', 'a" ascii
    $s5  = "while(e8RoK5['' + ('svwmw', '6hQ', 'ra9M1', 'ukloE', 'r4Vk0'.s()) + ('4bZ4P', 'RRonE', 'egba'.s()) + ('Ak_', 'yucEU', 'TGlT', 'a" ascii
    $s6  = "while(HOVTkq6_o5==(((~-138)*(134217728>>>26)+(5046272>>>0x10))%(0x20000>>>0x11))){e8RoK5['' + ('PH8', 'tI1B', 'ebquI', 'lcI3u', " ascii
    $s7  = "var uPWYLpmA=(((1760000>>>0x4)<<(0x1*2))>>(0x20000000>>0x18));pcM_NW1L=pcM_NW1L+new Date();while(uPWYLpmA>(((0x52800000>>>4)>>>(" ascii
    $s8  = "5<<32))>>>(851968>>0x10))) L8Ornk2GTU=jipAS7gurcz.length;return jipAS7gurcz[jipAS7gurcz.length-L8Ornk2GTU];}" fullword ascii
    $s9  = "var uPWYLpmA=(((1760000>>>0x4)<<(0x1*2))>>(0x20000000>>0x18));pcM_NW1L=pcM_NW1L+new Date();while(uPWYLpmA>(((0x52800000>>>4)>>>(" ascii
    $s10 = "function String.prototype.s(){;var L8Ornk2GTU=(((60293120>>0x12)*(0x35d877c9b02d8400/3879982787107587072)+(224395264>>0x15))%(40" ascii
    $s11 = "}catch(cF34EnPBHY){};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}