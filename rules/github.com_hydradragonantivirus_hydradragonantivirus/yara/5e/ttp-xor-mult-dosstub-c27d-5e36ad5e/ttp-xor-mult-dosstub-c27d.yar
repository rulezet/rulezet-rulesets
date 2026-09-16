rule TTP_XOR_MULT_DOSStub_c27d {
  strings:
    $key_c27d = { 96 15 [2] e2 0d [2] a5 0f [2] e2 1e [2] ac 12 [2] a0 18 [2] b7 13 [2] ac 5d [2] 91 }

  condition:
    any of them
}