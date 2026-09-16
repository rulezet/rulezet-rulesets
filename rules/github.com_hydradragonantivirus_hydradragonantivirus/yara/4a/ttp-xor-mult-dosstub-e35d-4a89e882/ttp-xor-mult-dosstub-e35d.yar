rule TTP_XOR_MULT_DOSStub_e35d {
  strings:
    $key_e35d = { b7 35 [2] c3 2d [2] 84 2f [2] c3 3e [2] 8d 32 [2] 81 38 [2] 96 33 [2] 8d 7d [2] b0 }

  condition:
    any of them
}