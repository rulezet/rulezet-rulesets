rule TTP_XOR_MULT_DOSStub_c06f {
  strings:
    $key_c06f = { 94 07 [2] e0 1f [2] a7 1d [2] e0 0c [2] ae 00 [2] a2 0a [2] b5 01 [2] ae 4f [2] 93 }

  condition:
    any of them
}