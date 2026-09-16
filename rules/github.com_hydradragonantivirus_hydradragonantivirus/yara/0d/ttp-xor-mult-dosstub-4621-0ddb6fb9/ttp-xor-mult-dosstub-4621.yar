rule TTP_XOR_MULT_DOSStub_4621 {
  strings:
    $key_4621 = { 12 49 [2] 66 51 [2] 21 53 [2] 66 42 [2] 28 4e [2] 24 44 [2] 33 4f [2] 28 01 [2] 15 }

  condition:
    any of them
}