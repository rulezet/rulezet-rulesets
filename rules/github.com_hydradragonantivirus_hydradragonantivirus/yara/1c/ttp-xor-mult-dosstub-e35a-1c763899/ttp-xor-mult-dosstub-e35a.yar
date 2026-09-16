rule TTP_XOR_MULT_DOSStub_e35a {
  strings:
    $key_e35a = { b7 32 [2] c3 2a [2] 84 28 [2] c3 39 [2] 8d 35 [2] 81 3f [2] 96 34 [2] 8d 7a [2] b0 }

  condition:
    any of them
}