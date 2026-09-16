rule TTP_XOR_MULT_DOSStub_c275 {
  strings:
    $key_c275 = { 96 1d [2] e2 05 [2] a5 07 [2] e2 16 [2] ac 1a [2] a0 10 [2] b7 1b [2] ac 55 [2] 91 }

  condition:
    any of them
}