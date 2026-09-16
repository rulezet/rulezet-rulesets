rule TTP_XOR_MULT_DOSStub_b7ee {
  strings:
    $key_b7ee = { e3 86 [2] 97 9e [2] d0 9c [2] 97 8d [2] d9 81 [2] d5 8b [2] c2 80 [2] d9 ce [2] e4 }

  condition:
    any of them
}