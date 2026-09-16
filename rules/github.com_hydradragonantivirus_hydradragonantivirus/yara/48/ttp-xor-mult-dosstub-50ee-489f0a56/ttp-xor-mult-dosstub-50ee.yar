rule TTP_XOR_MULT_DOSStub_50ee {
  strings:
    $key_50ee = { 04 86 [2] 70 9e [2] 37 9c [2] 70 8d [2] 3e 81 [2] 32 8b [2] 25 80 [2] 3e ce [2] 03 }

  condition:
    any of them
}