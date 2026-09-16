rule TTP_XOR_MULT_DOSStub_0d40 {
  strings:
    $key_0d40 = { 59 28 [2] 2d 30 [2] 6a 32 [2] 2d 23 [2] 63 2f [2] 6f 25 [2] 78 2e [2] 63 60 [2] 5e }

  condition:
    any of them
}