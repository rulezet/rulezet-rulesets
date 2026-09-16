rule TTP_XOR_MULT_DOSStub_39ee {
  strings:
    $key_39ee = { 6d 86 [2] 19 9e [2] 5e 9c [2] 19 8d [2] 57 81 [2] 5b 8b [2] 4c 80 [2] 57 ce [2] 6a }

  condition:
    any of them
}