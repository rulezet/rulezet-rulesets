rule TTP_XOR_MULT_DOSStub_c206 {
  strings:
    $key_c206 = { 96 6e [2] e2 76 [2] a5 74 [2] e2 65 [2] ac 69 [2] a0 63 [2] b7 68 [2] ac 26 [2] 91 }

  condition:
    any of them
}