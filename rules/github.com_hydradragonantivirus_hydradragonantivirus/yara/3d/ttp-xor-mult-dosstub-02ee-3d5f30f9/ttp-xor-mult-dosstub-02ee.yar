rule TTP_XOR_MULT_DOSStub_02ee {
  strings:
    $key_02ee = { 56 86 [2] 22 9e [2] 65 9c [2] 22 8d [2] 6c 81 [2] 60 8b [2] 77 80 [2] 6c ce [2] 51 }

  condition:
    any of them
}