rule TTP_XOR_MULT_DOSStub_c2e3 {
  strings:
    $key_c2e3 = { 96 8b [2] e2 93 [2] a5 91 [2] e2 80 [2] ac 8c [2] a0 86 [2] b7 8d [2] ac c3 [2] 91 }

  condition:
    any of them
}