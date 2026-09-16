rule TTP_XOR_MULT_DOSStub_76ee {
  strings:
    $key_76ee = { 22 86 [2] 56 9e [2] 11 9c [2] 56 8d [2] 18 81 [2] 14 8b [2] 03 80 [2] 18 ce [2] 25 }

  condition:
    any of them
}