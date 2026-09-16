rule TTP_XOR_MULT_DOSStub_6162 {
  strings:
    $key_6162 = { 35 0a [2] 41 12 [2] 06 10 [2] 41 01 [2] 0f 0d [2] 03 07 [2] 14 0c [2] 0f 42 [2] 32 }

  condition:
    any of them
}