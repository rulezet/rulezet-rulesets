rule TTP_XOR_MULT_DOSStub_c07e {
  strings:
    $key_c07e = { 94 16 [2] e0 0e [2] a7 0c [2] e0 1d [2] ae 11 [2] a2 1b [2] b5 10 [2] ae 5e [2] 93 }

  condition:
    any of them
}