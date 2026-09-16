rule TTP_XOR_MULT_DOSStub_6143 {
  strings:
    $key_6143 = { 35 2b [2] 41 33 [2] 06 31 [2] 41 20 [2] 0f 2c [2] 03 26 [2] 14 2d [2] 0f 63 [2] 32 }

  condition:
    any of them
}