rule TTP_XOR_MULT_DOSStub_6115 {
  strings:
    $key_6115 = { 35 7d [2] 41 65 [2] 06 67 [2] 41 76 [2] 0f 7a [2] 03 70 [2] 14 7b [2] 0f 35 [2] 32 }

  condition:
    any of them
}