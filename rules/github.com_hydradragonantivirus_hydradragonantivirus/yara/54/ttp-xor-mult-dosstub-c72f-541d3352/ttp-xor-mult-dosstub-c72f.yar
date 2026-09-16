rule TTP_XOR_MULT_DOSStub_c72f {
  strings:
    $key_c72f = { 93 47 [2] e7 5f [2] a0 5d [2] e7 4c [2] a9 40 [2] a5 4a [2] b2 41 [2] a9 0f [2] 94 }

  condition:
    any of them
}