rule TTP_XOR_MULT_DOSStub_6411 {
  strings:
    $key_6411 = { 30 79 [2] 44 61 [2] 03 63 [2] 44 72 [2] 0a 7e [2] 06 74 [2] 11 7f [2] 0a 31 [2] 37 }

  condition:
    any of them
}