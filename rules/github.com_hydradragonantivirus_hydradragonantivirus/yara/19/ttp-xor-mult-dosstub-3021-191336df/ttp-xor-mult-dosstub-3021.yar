rule TTP_XOR_MULT_DOSStub_3021 {
  strings:
    $key_3021 = { 64 49 [2] 10 51 [2] 57 53 [2] 10 42 [2] 5e 4e [2] 52 44 [2] 45 4f [2] 5e 01 [2] 63 }

  condition:
    any of them
}