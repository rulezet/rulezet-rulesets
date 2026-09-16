rule TTP_XOR_MULT_DOSStub_1127 {
  strings:
    $key_1127 = { 45 4f [2] 31 57 [2] 76 55 [2] 31 44 [2] 7f 48 [2] 73 42 [2] 64 49 [2] 7f 07 [2] 42 }

  condition:
    any of them
}