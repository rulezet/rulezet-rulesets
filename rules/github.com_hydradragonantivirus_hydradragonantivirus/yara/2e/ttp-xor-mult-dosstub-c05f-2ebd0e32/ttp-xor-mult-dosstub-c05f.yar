rule TTP_XOR_MULT_DOSStub_c05f {
  strings:
    $key_c05f = { 94 37 [2] e0 2f [2] a7 2d [2] e0 3c [2] ae 30 [2] a2 3a [2] b5 31 [2] ae 7f [2] 93 }

  condition:
    any of them
}