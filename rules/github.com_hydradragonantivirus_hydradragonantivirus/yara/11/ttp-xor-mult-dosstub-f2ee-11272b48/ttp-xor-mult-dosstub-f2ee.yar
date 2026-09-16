rule TTP_XOR_MULT_DOSStub_f2ee {
  strings:
    $key_f2ee = { a6 86 [2] d2 9e [2] 95 9c [2] d2 8d [2] 9c 81 [2] 90 8b [2] 87 80 [2] 9c ce [2] a1 }

  condition:
    any of them
}