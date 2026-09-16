rule TTP_XOR_MULT_DOSStub_10ee {
  strings:
    $key_10ee = { 44 86 [2] 30 9e [2] 77 9c [2] 30 8d [2] 7e 81 [2] 72 8b [2] 65 80 [2] 7e ce [2] 43 }

  condition:
    any of them
}