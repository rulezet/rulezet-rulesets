rule TTP_XOR_MULT_DOSStub_c24c {
  strings:
    $key_c24c = { 96 24 [2] e2 3c [2] a5 3e [2] e2 2f [2] ac 23 [2] a0 29 [2] b7 22 [2] ac 6c [2] 91 }

  condition:
    any of them
}