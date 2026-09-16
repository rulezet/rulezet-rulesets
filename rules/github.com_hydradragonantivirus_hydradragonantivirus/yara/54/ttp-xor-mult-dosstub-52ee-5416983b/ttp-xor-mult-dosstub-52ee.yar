rule TTP_XOR_MULT_DOSStub_52ee {
  strings:
    $key_52ee = { 06 86 [2] 72 9e [2] 35 9c [2] 72 8d [2] 3c 81 [2] 30 8b [2] 27 80 [2] 3c ce [2] 01 }

  condition:
    any of them
}