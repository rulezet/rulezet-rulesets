rule TTP_XOR_MULT_DOSStub_0721 {
  strings:
    $key_0721 = { 53 49 [2] 27 51 [2] 60 53 [2] 27 42 [2] 69 4e [2] 65 44 [2] 72 4f [2] 69 01 [2] 54 }

  condition:
    any of them
}