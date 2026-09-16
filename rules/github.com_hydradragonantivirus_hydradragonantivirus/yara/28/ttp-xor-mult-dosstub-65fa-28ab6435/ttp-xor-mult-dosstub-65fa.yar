rule TTP_XOR_MULT_DOSStub_65fa {
  strings:
    $key_65fa = { 31 92 [2] 45 8a [2] 02 88 [2] 45 99 [2] 0b 95 [2] 07 9f [2] 10 94 [2] 0b da [2] 36 }

  condition:
    any of them
}