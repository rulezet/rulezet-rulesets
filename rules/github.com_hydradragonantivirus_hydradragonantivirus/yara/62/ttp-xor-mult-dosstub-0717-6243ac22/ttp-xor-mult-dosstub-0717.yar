rule TTP_XOR_MULT_DOSStub_0717 {
  strings:
    $key_0717 = { 53 7f [2] 27 67 [2] 60 65 [2] 27 74 [2] 69 78 [2] 65 72 [2] 72 79 [2] 69 37 [2] 54 }

  condition:
    any of them
}