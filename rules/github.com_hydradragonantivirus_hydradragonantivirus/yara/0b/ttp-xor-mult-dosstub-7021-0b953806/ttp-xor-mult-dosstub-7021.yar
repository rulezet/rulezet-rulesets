rule TTP_XOR_MULT_DOSStub_7021 {
  strings:
    $key_7021 = { 24 49 [2] 50 51 [2] 17 53 [2] 50 42 [2] 1e 4e [2] 12 44 [2] 05 4f [2] 1e 01 [2] 23 }

  condition:
    any of them
}