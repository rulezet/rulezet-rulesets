rule TTP_XOR_MULT_DOSStub_38ee {
  strings:
    $key_38ee = { 6c 86 [2] 18 9e [2] 5f 9c [2] 18 8d [2] 56 81 [2] 5a 8b [2] 4d 80 [2] 56 ce [2] 6b }

  condition:
    any of them
}