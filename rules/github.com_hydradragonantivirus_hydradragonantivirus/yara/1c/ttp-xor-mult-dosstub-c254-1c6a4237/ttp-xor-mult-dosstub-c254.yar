rule TTP_XOR_MULT_DOSStub_c254 {
  strings:
    $key_c254 = { 96 3c [2] e2 24 [2] a5 26 [2] e2 37 [2] ac 3b [2] a0 31 [2] b7 3a [2] ac 74 [2] 91 }

  condition:
    any of them
}