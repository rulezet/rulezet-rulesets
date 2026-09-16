rule TTP_XOR_MULT_DOSStub_c211 {
  strings:
    $key_c211 = { 96 79 [2] e2 61 [2] a5 63 [2] e2 72 [2] ac 7e [2] a0 74 [2] b7 7f [2] ac 31 [2] 91 }

  condition:
    any of them
}