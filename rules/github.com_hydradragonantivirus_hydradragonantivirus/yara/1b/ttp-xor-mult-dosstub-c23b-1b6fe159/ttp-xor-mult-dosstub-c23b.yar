rule TTP_XOR_MULT_DOSStub_c23b {
  strings:
    $key_c23b = { 96 53 [2] e2 4b [2] a5 49 [2] e2 58 [2] ac 54 [2] a0 5e [2] b7 55 [2] ac 1b [2] 91 }

  condition:
    any of them
}