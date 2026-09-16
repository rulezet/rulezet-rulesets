rule TTP_XOR_MULT_DOSStub_5237 {
  strings:
    $key_5237 = { 06 5f [2] 72 47 [2] 35 45 [2] 72 54 [2] 3c 58 [2] 30 52 [2] 27 59 [2] 3c 17 [2] 01 }

  condition:
    any of them
}