rule TTP_XOR_MULT_DOSStub_c27b {
  strings:
    $key_c27b = { 96 13 [2] e2 0b [2] a5 09 [2] e2 18 [2] ac 14 [2] a0 1e [2] b7 15 [2] ac 5b [2] 91 }

  condition:
    any of them
}