rule TTP_XOR_MULT_DOSStub_6158 {
  strings:
    $key_6158 = { 35 30 [2] 41 28 [2] 06 2a [2] 41 3b [2] 0f 37 [2] 03 3d [2] 14 36 [2] 0f 78 [2] 32 }

  condition:
    any of them
}