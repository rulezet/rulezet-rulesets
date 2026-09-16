rule TTP_XOR_MULT_DOSStub_08ee {
  strings:
    $key_08ee = { 5c 86 [2] 28 9e [2] 6f 9c [2] 28 8d [2] 66 81 [2] 6a 8b [2] 7d 80 [2] 66 ce [2] 5b }

  condition:
    any of them
}