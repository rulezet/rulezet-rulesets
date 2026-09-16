rule TTP_XOR_MULT_DOSStub_66f8 {
  strings:
    $key_66f8 = { 32 90 [2] 46 88 [2] 01 8a [2] 46 9b [2] 08 97 [2] 04 9d [2] 13 96 [2] 08 d8 [2] 35 }

  condition:
    any of them
}