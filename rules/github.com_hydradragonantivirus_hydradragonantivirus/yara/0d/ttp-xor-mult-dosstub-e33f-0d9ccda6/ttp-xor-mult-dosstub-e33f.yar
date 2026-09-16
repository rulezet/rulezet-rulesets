rule TTP_XOR_MULT_DOSStub_e33f {
  strings:
    $key_e33f = { b7 57 [2] c3 4f [2] 84 4d [2] c3 5c [2] 8d 50 [2] 81 5a [2] 96 51 [2] 8d 1f [2] b0 }

  condition:
    any of them
}