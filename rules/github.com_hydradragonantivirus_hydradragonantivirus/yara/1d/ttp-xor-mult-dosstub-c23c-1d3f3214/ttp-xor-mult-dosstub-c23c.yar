rule TTP_XOR_MULT_DOSStub_c23c {
  strings:
    $key_c23c = { 96 54 [2] e2 4c [2] a5 4e [2] e2 5f [2] ac 53 [2] a0 59 [2] b7 52 [2] ac 1c [2] 91 }

  condition:
    any of them
}