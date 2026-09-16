rule TTP_XOR_MULT_DOSStub_c07f {
  strings:
    $key_c07f = { 94 17 [2] e0 0f [2] a7 0d [2] e0 1c [2] ae 10 [2] a2 1a [2] b5 11 [2] ae 5f [2] 93 }

  condition:
    any of them
}