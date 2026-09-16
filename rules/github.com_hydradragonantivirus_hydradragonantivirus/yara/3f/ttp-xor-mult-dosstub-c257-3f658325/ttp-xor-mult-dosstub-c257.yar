rule TTP_XOR_MULT_DOSStub_c257 {
  strings:
    $key_c257 = { 96 3f [2] e2 27 [2] a5 25 [2] e2 34 [2] ac 38 [2] a0 32 [2] b7 39 [2] ac 77 [2] 91 }

  condition:
    any of them
}