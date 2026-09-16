rule TTP_XOR_MULT_DOSStub_30ee {
  strings:
    $key_30ee = { 64 86 [2] 10 9e [2] 57 9c [2] 10 8d [2] 5e 81 [2] 52 8b [2] 45 80 [2] 5e ce [2] 63 }

  condition:
    any of them
}