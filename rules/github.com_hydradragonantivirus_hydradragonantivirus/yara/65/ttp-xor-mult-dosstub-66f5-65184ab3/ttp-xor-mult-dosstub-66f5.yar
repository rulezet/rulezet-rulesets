rule TTP_XOR_MULT_DOSStub_66f5 {
  strings:
    $key_66f5 = { 32 9d [2] 46 85 [2] 01 87 [2] 46 96 [2] 08 9a [2] 04 90 [2] 13 9b [2] 08 d5 [2] 35 }

  condition:
    any of them
}