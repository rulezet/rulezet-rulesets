rule TTP_XOR_MULT_DOSStub_6155 {
  strings:
    $key_6155 = { 35 3d [2] 41 25 [2] 06 27 [2] 41 36 [2] 0f 3a [2] 03 30 [2] 14 3b [2] 0f 75 [2] 32 }

  condition:
    any of them
}