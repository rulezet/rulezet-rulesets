rule TTP_XOR_MULT_DOSStub_6152 {
  strings:
    $key_6152 = { 35 3a [2] 41 22 [2] 06 20 [2] 41 31 [2] 0f 3d [2] 03 37 [2] 14 3c [2] 0f 72 [2] 32 }

  condition:
    any of them
}