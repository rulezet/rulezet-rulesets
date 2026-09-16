rule TTP_XOR_MULT_DOSStub_09ee {
  strings:
    $key_09ee = { 5d 86 [2] 29 9e [2] 6e 9c [2] 29 8d [2] 67 81 [2] 6b 8b [2] 7c 80 [2] 67 ce [2] 5a }

  condition:
    any of them
}