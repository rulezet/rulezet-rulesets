rule TTP_XOR_MULT_DOSStub_c70f {
  strings:
    $key_c70f = { 93 67 [2] e7 7f [2] a0 7d [2] e7 6c [2] a9 60 [2] a5 6a [2] b2 61 [2] a9 2f [2] 94 }

  condition:
    any of them
}