rule TTP_XOR_MULT_DOSStub_c2ee {
  strings:
    $key_c2ee = { 96 86 [2] e2 9e [2] a5 9c [2] e2 8d [2] ac 81 [2] a0 8b [2] b7 80 [2] ac ce [2] 91 }

  condition:
    any of them
}