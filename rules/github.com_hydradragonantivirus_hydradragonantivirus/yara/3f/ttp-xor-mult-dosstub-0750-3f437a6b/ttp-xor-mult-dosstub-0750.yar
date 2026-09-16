rule TTP_XOR_MULT_DOSStub_0750 {
  strings:
    $key_0750 = { 53 38 [2] 27 20 [2] 60 22 [2] 27 33 [2] 69 3f [2] 65 35 [2] 72 3e [2] 69 70 [2] 54 }

  condition:
    any of them
}