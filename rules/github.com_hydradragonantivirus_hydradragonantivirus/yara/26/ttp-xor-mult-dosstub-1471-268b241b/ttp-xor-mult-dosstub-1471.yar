rule TTP_XOR_MULT_DOSStub_1471 {
  strings:
    $key_1471 = { 40 19 [2] 34 01 [2] 73 03 [2] 34 12 [2] 7a 1e [2] 76 14 [2] 61 1f [2] 7a 51 [2] 47 }

  condition:
    any of them
}