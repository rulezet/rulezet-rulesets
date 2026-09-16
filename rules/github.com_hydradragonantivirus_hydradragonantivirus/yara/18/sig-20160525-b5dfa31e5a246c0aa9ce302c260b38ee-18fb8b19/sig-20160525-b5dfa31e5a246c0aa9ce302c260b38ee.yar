rule sig_20160525_b5dfa31e5a246c0aa9ce302c260b38ee {
  meta:
    description = "datamaliciousorder - file 20160525_b5dfa31e5a246c0aa9ce302c260b38ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c561385d04e20cfb1d4b511473c24e92171fe60f4b3e37b9bae9932954382f67"

  strings:
    $s1 = "d+)ecapsetihwxelfd(modnard + keppeld+md+dnenoisillocd + suidarelcitrapd+imc + rerednerc+)ssorcac(tsilslianbmuhtoc ,)modnarc(deer" ascii
    $s2 = "+ sdnetv[eixodb    \\n;)(]gsml[eixodb    \\n         ;mb = ]rerednerp + cthp[eixodb    \\n;tsilslianbmuhtoa = ]dnenoisillocn + s" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}