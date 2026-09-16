rule TTP_XOR_MULT_DOSStub_7950 {
  strings:
    $key_7950 = { 2d 38 [2] 59 20 [2] 1e 22 [2] 59 33 [2] 17 3f [2] 1b 35 [2] 0c 3e [2] 17 70 [2] 2a }

  condition:
    any of them
}