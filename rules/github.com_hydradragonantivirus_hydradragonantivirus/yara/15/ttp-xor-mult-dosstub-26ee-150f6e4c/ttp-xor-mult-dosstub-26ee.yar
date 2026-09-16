rule TTP_XOR_MULT_DOSStub_26ee {
  strings:
    $key_26ee = { 72 86 [2] 06 9e [2] 41 9c [2] 06 8d [2] 48 81 [2] 44 8b [2] 53 80 [2] 48 ce [2] 75 }

  condition:
    any of them
}