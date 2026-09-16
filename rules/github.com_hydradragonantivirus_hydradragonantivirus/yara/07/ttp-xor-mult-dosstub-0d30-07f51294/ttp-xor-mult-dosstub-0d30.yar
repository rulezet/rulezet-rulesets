rule TTP_XOR_MULT_DOSStub_0d30 {
  strings:
    $key_0d30 = { 59 58 [2] 2d 40 [2] 6a 42 [2] 2d 53 [2] 63 5f [2] 6f 55 [2] 78 5e [2] 63 10 [2] 5e }

  condition:
    any of them
}