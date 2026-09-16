rule TTP_XOR_MULT_DOSStub_c00f {
  strings:
    $key_c00f = { 94 67 [2] e0 7f [2] a7 7d [2] e0 6c [2] ae 60 [2] a2 6a [2] b5 61 [2] ae 2f [2] 93 }

  condition:
    any of them
}