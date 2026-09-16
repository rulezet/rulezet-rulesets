rule TTP_XOR_MULT_DOSStub_e31a {
  strings:
    $key_e31a = { b7 72 [2] c3 6a [2] 84 68 [2] c3 79 [2] 8d 75 [2] 81 7f [2] 96 74 [2] 8d 3a [2] b0 }

  condition:
    any of them
}