rule TTP_XOR_MULT_DOSStub_6840 {
  strings:
    $key_6840 = { 3c 28 [2] 48 30 [2] 0f 32 [2] 48 23 [2] 06 2f [2] 0a 25 [2] 1d 2e [2] 06 60 [2] 3b }

  condition:
    any of them
}