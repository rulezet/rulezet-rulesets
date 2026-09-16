rule TTP_XOR_MULT_DOSStub_c276 {
  strings:
    $key_c276 = { 96 1e [2] e2 06 [2] a5 04 [2] e2 15 [2] ac 19 [2] a0 13 [2] b7 18 [2] ac 56 [2] 91 }

  condition:
    any of them
}