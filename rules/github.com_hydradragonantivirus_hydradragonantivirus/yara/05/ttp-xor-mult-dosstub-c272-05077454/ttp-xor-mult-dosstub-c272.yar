rule TTP_XOR_MULT_DOSStub_c272 {
  strings:
    $key_c272 = { 96 1a [2] e2 02 [2] a5 00 [2] e2 11 [2] ac 1d [2] a0 17 [2] b7 1c [2] ac 52 [2] 91 }

  condition:
    any of them
}