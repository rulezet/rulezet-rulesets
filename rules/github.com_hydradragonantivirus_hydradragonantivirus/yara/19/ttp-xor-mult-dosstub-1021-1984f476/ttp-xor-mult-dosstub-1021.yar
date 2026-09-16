rule TTP_XOR_MULT_DOSStub_1021 {
  strings:
    $key_1021 = { 44 49 [2] 30 51 [2] 77 53 [2] 30 42 [2] 7e 4e [2] 72 44 [2] 65 4f [2] 7e 01 [2] 43 }

  condition:
    any of them
}