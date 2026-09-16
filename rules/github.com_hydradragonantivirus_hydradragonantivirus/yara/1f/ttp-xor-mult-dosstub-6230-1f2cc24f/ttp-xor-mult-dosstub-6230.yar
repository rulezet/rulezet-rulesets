rule TTP_XOR_MULT_DOSStub_6230 {
  strings:
    $key_6230 = { 36 58 [2] 42 40 [2] 05 42 [2] 42 53 [2] 0c 5f [2] 00 55 [2] 17 5e [2] 0c 10 [2] 31 }

  condition:
    any of them
}