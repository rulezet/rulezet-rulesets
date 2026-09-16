rule TTP_XOR_MULT_DOSStub_4a50 {
  strings:
    $key_4a50 = { 1e 38 [2] 6a 20 [2] 2d 22 [2] 6a 33 [2] 24 3f [2] 28 35 [2] 3f 3e [2] 24 70 [2] 19 }

  condition:
    any of them
}