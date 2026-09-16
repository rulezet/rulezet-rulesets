rule TTP_XOR_MULT_DOSStub_18ee {
  strings:
    $key_18ee = { 4c 86 [2] 38 9e [2] 7f 9c [2] 38 8d [2] 76 81 [2] 7a 8b [2] 6d 80 [2] 76 ce [2] 4b }

  condition:
    any of them
}