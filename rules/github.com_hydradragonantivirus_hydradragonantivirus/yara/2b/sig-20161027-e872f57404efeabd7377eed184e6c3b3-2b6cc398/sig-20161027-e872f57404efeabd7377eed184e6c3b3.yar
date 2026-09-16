rule sig_20161027_e872f57404efeabd7377eed184e6c3b3 {
  meta:
    description = "datamaliciousorder - file 20161027_e872f57404efeabd7377eed184e6c3b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "284a957c1d17b53e60f299466ff30def8b764bad1245bef99292e5f94bccf5a9"

  strings:
    $s1  = "this.split(\"\");if (Number(J1SicJA[3+pYqwZBQr.length*(2+4)]) - (((1140850688>>0x4)>>>(~-4))>>(4*4+0x3)) == (((31984<<0x6)<<(187" ascii
    $s2  = "function String.prototype.H(){var XM8US83AzI=(((~-57)*(0x4e83066f3f903000/5657372631785025536)+(0xd<<0x20))%(~-2));var pYqwZBQr=" ascii
    $s3  = "while(asxlhJxH_['' + 'r' + ('nlrn', 'Ek2y', 'i52n', 'eW'.H()) + ('2xtw', 'v8', 'HNyc9', 'ri', 'aztbc'.H()) + ('Po_b', 'rgMZD', '" ascii
    $s4  = "while(asxlhJxH_['' + 'r' + ('nlrn', 'Ek2y', 'i52n', 'eW'.H()) + ('2xtw', 'v8', 'HNyc9', 'ri', 'aztbc'.H()) + ('Po_b', 'rgMZD', '" ascii
    $s5  = "while(kk7_eBRWxA==(((208239311*1+0x9a68531)>>>(~-21))%(0x1088e6b64f378a00/0x1088e6b64f378a00))){ asxlhJxH_['' + ('Puk', 'nMrMf'," ascii
    $s6  = "while(kk7_eBRWxA==(((208239311*1+0x9a68531)>>>(~-21))%(0x1088e6b64f378a00/0x1088e6b64f378a00))){ asxlhJxH_['' + ('Puk', 'nMrMf'," ascii
    $s7  = "function String.prototype.H(){var XM8US83AzI=(((~-57)*(0x4e83066f3f903000/5657372631785025536)+(0xd<<0x20))%(~-2));var pYqwZBQr=" ascii
    $s8  = "48192>>>28))>>(71303168>>>22))) XM8US83AzI=pYqwZBQr.length;return pYqwZBQr[pYqwZBQr.length-XM8US83AzI];}" fullword ascii
    $s9  = "Kryte=' ';Sty5='';J1SicJA=[];Sty5=Sty5+new Date();var lY7awuZJQg5=(((0x1b6*0x1+248)<<(1*0x2))*(9<<0x3)+(0x95f*0x1+33));while(lY7" ascii
    $s10 = "Kryte=' ';Sty5='';J1SicJA=[];Sty5=Sty5+new Date();var lY7awuZJQg5=(((0x1b6*0x1+248)<<(1*0x2))*(9<<0x3)+(0x95f*0x1+33));while(lY7" ascii
    $s11 = "}catch(UFAPSIZZOfT2){};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}