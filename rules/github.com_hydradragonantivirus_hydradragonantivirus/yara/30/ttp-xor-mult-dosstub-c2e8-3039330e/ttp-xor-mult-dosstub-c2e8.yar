rule TTP_XOR_MULT_DOSStub_c2e8 {
  strings:
    $key_c2e8 = { 96 80 [2] e2 98 [2] a5 9a [2] e2 8b [2] ac 87 [2] a0 8d [2] b7 86 [2] ac c8 [2] 91 }

  condition:
    any of them
}