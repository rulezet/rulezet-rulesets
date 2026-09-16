rule TTP_XOR_MULT_DOSStub_1421 {
  strings:
    $key_1421 = { 40 49 [2] 34 51 [2] 73 53 [2] 34 42 [2] 7a 4e [2] 76 44 [2] 61 4f [2] 7a 01 [2] 47 }

  condition:
    any of them
}