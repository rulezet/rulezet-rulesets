rule TTP_XOR_MULT_DOSStub_27ee {
  strings:
    $key_27ee = { 73 86 [2] 07 9e [2] 40 9c [2] 07 8d [2] 49 81 [2] 45 8b [2] 52 80 [2] 49 ce [2] 74 }

  condition:
    any of them
}