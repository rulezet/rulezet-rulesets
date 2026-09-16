rule TTP_XOR_MULT_DOSStub_cdaa {
  strings:
    $key_cdaa = { 99 c2 [2] ed da [2] aa d8 [2] ed c9 [2] a3 c5 [2] af cf [2] b8 c4 [2] a3 8a [2] 9e }

  condition:
    any of them
}