rule TTP_XOR_MULT_DOSStub_0d50 {
  strings:
    $key_0d50 = { 59 38 [2] 2d 20 [2] 6a 22 [2] 2d 33 [2] 63 3f [2] 6f 35 [2] 78 3e [2] 63 70 [2] 5e }

  condition:
    any of them
}