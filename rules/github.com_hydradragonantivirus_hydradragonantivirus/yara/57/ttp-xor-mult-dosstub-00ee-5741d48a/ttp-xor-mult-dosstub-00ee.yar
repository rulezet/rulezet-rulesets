rule TTP_XOR_MULT_DOSStub_00ee {
  strings:
    $key_00ee = { 54 86 [2] 20 9e [2] 67 9c [2] 20 8d [2] 6e 81 [2] 62 8b [2] 75 80 [2] 6e ce [2] 53 }

  condition:
    any of them
}