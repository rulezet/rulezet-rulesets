rule TTP_XOR_MULT_DOSStub_0760 {
  strings:
    $key_0760 = { 53 08 [2] 27 10 [2] 60 12 [2] 27 03 [2] 69 0f [2] 65 05 [2] 72 0e [2] 69 40 [2] 54 }

  condition:
    any of them
}