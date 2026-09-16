rule TTP_XOR_MULT_DOSStub_aea8 {
  strings:
    $key_aea8 = { fa c0 [2] 8e d8 [2] c9 da [2] 8e cb [2] c0 c7 [2] cc cd [2] db c6 [2] c0 88 [2] fd }

  condition:
    any of them
}