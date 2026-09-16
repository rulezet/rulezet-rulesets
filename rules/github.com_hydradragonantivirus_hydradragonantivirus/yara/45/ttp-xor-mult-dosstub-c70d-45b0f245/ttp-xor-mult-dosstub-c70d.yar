rule TTP_XOR_MULT_DOSStub_c70d {
  strings:
    $key_c70d = { 93 65 [2] e7 7d [2] a0 7f [2] e7 6e [2] a9 62 [2] a5 68 [2] b2 63 [2] a9 2d [2] 94 }

  condition:
    any of them
}