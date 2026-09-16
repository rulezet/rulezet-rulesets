rule TTP_XOR_MULT_DOSStub_7721 {
  strings:
    $key_7721 = { 23 49 [2] 57 51 [2] 10 53 [2] 57 42 [2] 19 4e [2] 15 44 [2] 02 4f [2] 19 01 [2] 24 }

  condition:
    any of them
}