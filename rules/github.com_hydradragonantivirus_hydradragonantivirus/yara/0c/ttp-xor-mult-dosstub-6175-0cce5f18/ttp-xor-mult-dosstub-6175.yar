rule TTP_XOR_MULT_DOSStub_6175 {
  strings:
    $key_6175 = { 35 1d [2] 41 05 [2] 06 07 [2] 41 16 [2] 0f 1a [2] 03 10 [2] 14 1b [2] 0f 55 [2] 32 }

  condition:
    any of them
}