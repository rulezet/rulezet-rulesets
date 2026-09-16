rule TTP_XOR_MULT_DOSStub_3521 {
  strings:
    $key_3521 = { 61 49 [2] 15 51 [2] 52 53 [2] 15 42 [2] 5b 4e [2] 57 44 [2] 40 4f [2] 5b 01 [2] 66 }

  condition:
    any of them
}