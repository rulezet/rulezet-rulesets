rule TTP_XOR_MULT_DOSStub_c241 {
  strings:
    $key_c241 = { 96 29 [2] e2 31 [2] a5 33 [2] e2 22 [2] ac 2e [2] a0 24 [2] b7 2f [2] ac 61 [2] 91 }

  condition:
    any of them
}