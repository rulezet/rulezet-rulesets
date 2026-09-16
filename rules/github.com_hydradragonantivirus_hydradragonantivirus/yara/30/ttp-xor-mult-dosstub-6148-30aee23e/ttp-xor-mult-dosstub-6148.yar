rule TTP_XOR_MULT_DOSStub_6148 {
  strings:
    $key_6148 = { 35 20 [2] 41 38 [2] 06 3a [2] 41 2b [2] 0f 27 [2] 03 2d [2] 14 26 [2] 0f 68 [2] 32 }

  condition:
    any of them
}