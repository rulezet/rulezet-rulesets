rule TTP_XOR_MULT_DOSStub_21ee {
  strings:
    $key_21ee = { 75 86 [2] 01 9e [2] 46 9c [2] 01 8d [2] 4f 81 [2] 43 8b [2] 54 80 [2] 4f ce [2] 72 }

  condition:
    any of them
}