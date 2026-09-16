rule TTP_XOR_MULT_DOSStub_c270 {
  strings:
    $key_c270 = { 96 18 [2] e2 00 [2] a5 02 [2] e2 13 [2] ac 1f [2] a0 15 [2] b7 1e [2] ac 50 [2] 91 }

  condition:
    any of them
}