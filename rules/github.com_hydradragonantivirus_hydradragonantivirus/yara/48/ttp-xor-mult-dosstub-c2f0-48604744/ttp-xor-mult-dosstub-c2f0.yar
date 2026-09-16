rule TTP_XOR_MULT_DOSStub_c2f0 {
  strings:
    $key_c2f0 = { 96 98 [2] e2 80 [2] a5 82 [2] e2 93 [2] ac 9f [2] a0 95 [2] b7 9e [2] ac d0 [2] 91 }

  condition:
    any of them
}