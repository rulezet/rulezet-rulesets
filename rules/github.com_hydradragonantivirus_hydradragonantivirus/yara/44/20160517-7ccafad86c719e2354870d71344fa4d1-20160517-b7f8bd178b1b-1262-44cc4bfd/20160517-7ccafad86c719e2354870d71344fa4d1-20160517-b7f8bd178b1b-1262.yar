rule _20160517_7ccafad86c719e2354870d71344fa4d1_20160517_b7f8bd178b1b_1262 {
  meta:
    description = "datamaliciousorder - from files 20160517_7ccafad86c719e2354870d71344fa4d1.js, 20160517_b7f8bd178b1b0d7647c494350a80fc1a.js, 20160517_cf904382b299fa0d149d305dd7b09466.js, 20160517_daa335d20e5fc70b6f1e3fc04fa0a9d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e912b281d3d5c9eb197300f107e048b3d52deb2202b88474eb259a6ea4ca865"
    hash2       = "237d9f382b5b3797f81cee233886e0f79291a3c8c3d1697dccf19b56b001f7b9"
    hash3       = "0c528302d50b810be83ab4c46033c78bdb7b476ac49b9afe305c02388da36a97"
    hash4       = "58cdd6a46036852d6cc442c406c6924f33cb0470106f58274e5f4cd4f86d7a25"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* R  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* R  */ = (123, Turkey); return devel0 /* R  */;};" fullword ascii
    $s3 = "function Scott /* R  */(accinp0 /* R  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* R  */(accinp0 /* R  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* R  */= true;/* R  */" fullword ascii
    $s6 = "place = /* R  */(/* R  */\"noitisop\").split(''/* R  */).reverse(/* R  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}