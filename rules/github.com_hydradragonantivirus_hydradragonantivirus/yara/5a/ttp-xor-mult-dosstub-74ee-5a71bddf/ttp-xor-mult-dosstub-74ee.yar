rule TTP_XOR_MULT_DOSStub_74ee {
  strings:
    $key_74ee = { 20 86 [2] 54 9e [2] 13 9c [2] 54 8d [2] 1a 81 [2] 16 8b [2] 01 80 [2] 1a ce [2] 27 }

  condition:
    any of them
}