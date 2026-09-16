rule TTP_XOR_MULT_DOSStub_1230 {
  strings:
    $key_1230 = { 46 58 [2] 32 40 [2] 75 42 [2] 32 53 [2] 7c 5f [2] 70 55 [2] 67 5e [2] 7c 10 [2] 41 }

  condition:
    any of them
}