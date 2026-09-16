rule TTP_XOR_MULT_DOSStub_c240 {
  strings:
    $key_c240 = { 96 28 [2] e2 30 [2] a5 32 [2] e2 23 [2] ac 2f [2] a0 25 [2] b7 2e [2] ac 60 [2] 91 }

  condition:
    any of them
}