rule TTP_XOR_MULT_DOSStub_c25b {
  strings:
    $key_c25b = { 96 33 [2] e2 2b [2] a5 29 [2] e2 38 [2] ac 34 [2] a0 3e [2] b7 35 [2] ac 7b [2] 91 }

  condition:
    any of them
}