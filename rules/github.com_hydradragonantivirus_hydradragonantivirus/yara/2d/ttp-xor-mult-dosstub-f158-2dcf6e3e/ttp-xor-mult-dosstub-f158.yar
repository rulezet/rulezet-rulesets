rule TTP_XOR_MULT_DOSStub_f158 {
  strings:
    $key_f158 = { a5 30 [2] d1 28 [2] 96 2a [2] d1 3b [2] 9f 37 [2] 93 3d [2] 84 36 [2] 9f 78 [2] a2 }

  condition:
    any of them
}