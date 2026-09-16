rule TTP_XOR_MULT_DOSStub_c215 {
  strings:
    $key_c215 = { 96 7d [2] e2 65 [2] a5 67 [2] e2 76 [2] ac 7a [2] a0 70 [2] b7 7b [2] ac 35 [2] 91 }

  condition:
    any of them
}