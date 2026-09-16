rule TTP_XOR_MULT_DOSStub_c07d {
  strings:
    $key_c07d = { 94 15 [2] e0 0d [2] a7 0f [2] e0 1e [2] ae 12 [2] a2 18 [2] b5 13 [2] ae 5d [2] 93 }

  condition:
    any of them
}