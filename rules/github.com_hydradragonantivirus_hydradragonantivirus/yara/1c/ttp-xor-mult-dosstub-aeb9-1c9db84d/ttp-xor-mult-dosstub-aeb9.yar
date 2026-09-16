rule TTP_XOR_MULT_DOSStub_aeb9 {
  strings:
    $key_aeb9 = { fa d1 [2] 8e c9 [2] c9 cb [2] 8e da [2] c0 d6 [2] cc dc [2] db d7 [2] c0 99 [2] fd }

  condition:
    any of them
}