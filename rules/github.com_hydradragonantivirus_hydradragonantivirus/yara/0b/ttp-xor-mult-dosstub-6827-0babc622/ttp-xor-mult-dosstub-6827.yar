rule TTP_XOR_MULT_DOSStub_6827 {
  strings:
    $key_6827 = { 3c 4f [2] 48 57 [2] 0f 55 [2] 48 44 [2] 06 48 [2] 0a 42 [2] 1d 49 [2] 06 07 [2] 3b }

  condition:
    any of them
}