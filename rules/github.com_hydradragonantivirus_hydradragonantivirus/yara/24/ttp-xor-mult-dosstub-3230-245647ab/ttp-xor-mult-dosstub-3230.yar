rule TTP_XOR_MULT_DOSStub_3230 {
  strings:
    $key_3230 = { 66 58 [2] 12 40 [2] 55 42 [2] 12 53 [2] 5c 5f [2] 50 55 [2] 47 5e [2] 5c 10 [2] 61 }

  condition:
    any of them
}