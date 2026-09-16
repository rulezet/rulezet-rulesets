rule TTP_XOR_MULT_DOSStub_c230 {
  strings:
    $key_c230 = { 96 58 [2] e2 40 [2] a5 42 [2] e2 53 [2] ac 5f [2] a0 55 [2] b7 5e [2] ac 10 [2] 91 }

  condition:
    any of them
}