rule TTP_XOR_MULT_DOSStub_6102 {
  strings:
    $key_6102 = { 35 6a [2] 41 72 [2] 06 70 [2] 41 61 [2] 0f 6d [2] 03 67 [2] 14 6c [2] 0f 22 [2] 32 }

  condition:
    any of them
}