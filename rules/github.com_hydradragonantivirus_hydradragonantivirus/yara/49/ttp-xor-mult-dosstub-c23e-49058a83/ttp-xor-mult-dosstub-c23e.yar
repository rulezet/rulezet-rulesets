rule TTP_XOR_MULT_DOSStub_c23e {
  strings:
    $key_c23e = { 96 56 [2] e2 4e [2] a5 4c [2] e2 5d [2] ac 51 [2] a0 5b [2] b7 50 [2] ac 1e [2] 91 }

  condition:
    any of them
}