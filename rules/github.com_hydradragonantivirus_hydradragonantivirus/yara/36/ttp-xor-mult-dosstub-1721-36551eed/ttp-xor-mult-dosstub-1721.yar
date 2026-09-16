rule TTP_XOR_MULT_DOSStub_1721 {
  strings:
    $key_1721 = { 43 49 [2] 37 51 [2] 70 53 [2] 37 42 [2] 79 4e [2] 75 44 [2] 62 4f [2] 79 01 [2] 44 }

  condition:
    any of them
}