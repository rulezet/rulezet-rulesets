rule TTP_XOR_MULT_DOSStub_e638 {
  strings:
    $key_e638 = { b2 50 [2] c6 48 [2] 81 4a [2] c6 5b [2] 88 57 [2] 84 5d [2] 93 56 [2] 88 18 [2] b5 }

  condition:
    any of them
}