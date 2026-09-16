rule TTP_XOR_MULT_DOSStub_0d56 {
  strings:
    $key_0d56 = { 59 3e [2] 2d 26 [2] 6a 24 [2] 2d 35 [2] 63 39 [2] 6f 33 [2] 78 38 [2] 63 76 [2] 5e }

  condition:
    any of them
}