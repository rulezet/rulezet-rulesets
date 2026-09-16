rule TTP_XOR_MULT_DOSStub_b6ee {
  strings:
    $key_b6ee = { e2 86 [2] 96 9e [2] d1 9c [2] 96 8d [2] d8 81 [2] d4 8b [2] c3 80 [2] d8 ce [2] e5 }

  condition:
    any of them
}