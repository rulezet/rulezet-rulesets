rule TTP_XOR_MULT_DOSStub_6330 {
  strings:
    $key_6330 = { 37 58 [2] 43 40 [2] 04 42 [2] 43 53 [2] 0d 5f [2] 01 55 [2] 16 5e [2] 0d 10 [2] 30 }

  condition:
    any of them
}