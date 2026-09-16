rule TTP_XOR_MULT_DOSStub_c259 {
  strings:
    $key_c259 = { 96 31 [2] e2 29 [2] a5 2b [2] e2 3a [2] ac 36 [2] a0 3c [2] b7 37 [2] ac 79 [2] 91 }

  condition:
    any of them
}