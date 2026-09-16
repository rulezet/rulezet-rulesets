rule TTP_XOR_MULT_DOSStub_5211 {
  strings:
    $key_5211 = { 06 79 [2] 72 61 [2] 35 63 [2] 72 72 [2] 3c 7e [2] 30 74 [2] 27 7f [2] 3c 31 [2] 01 }

  condition:
    any of them
}