rule TTP_XOR_MULT_DOSStub_4a21 {
  strings:
    $key_4a21 = { 1e 49 [2] 6a 51 [2] 2d 53 [2] 6a 42 [2] 24 4e [2] 28 44 [2] 3f 4f [2] 24 01 [2] 19 }

  condition:
    any of them
}