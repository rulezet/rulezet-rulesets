rule TTP_XOR_MULT_DOSStub_c2f6 {
  strings:
    $key_c2f6 = { 96 9e [2] e2 86 [2] a5 84 [2] e2 95 [2] ac 99 [2] a0 93 [2] b7 98 [2] ac d6 [2] 91 }

  condition:
    any of them
}