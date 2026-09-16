rule TTP_XOR_MULT_DOSStub_c21b {
  strings:
    $key_c21b = { 96 73 [2] e2 6b [2] a5 69 [2] e2 78 [2] ac 74 [2] a0 7e [2] b7 75 [2] ac 3b [2] 91 }

  condition:
    any of them
}