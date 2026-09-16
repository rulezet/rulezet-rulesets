rule TTP_XOR_MULT_DOSStub_c2e5 {
  strings:
    $key_c2e5 = { 96 8d [2] e2 95 [2] a5 97 [2] e2 86 [2] ac 8a [2] a0 80 [2] b7 8b [2] ac c5 [2] 91 }

  condition:
    any of them
}