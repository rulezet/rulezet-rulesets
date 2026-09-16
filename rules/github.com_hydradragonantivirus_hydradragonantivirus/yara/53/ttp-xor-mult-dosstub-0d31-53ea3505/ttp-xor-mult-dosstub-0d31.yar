rule TTP_XOR_MULT_DOSStub_0d31 {
  strings:
    $key_0d31 = { 59 59 [2] 2d 41 [2] 6a 43 [2] 2d 52 [2] 63 5e [2] 6f 54 [2] 78 5f [2] 63 11 [2] 5e }

  condition:
    any of them
}