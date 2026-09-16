rule TTP_XOR_MULT_DOSStub_c23d {
  strings:
    $key_c23d = { 96 55 [2] e2 4d [2] a5 4f [2] e2 5e [2] ac 52 [2] a0 58 [2] b7 53 [2] ac 1d [2] 91 }

  condition:
    any of them
}