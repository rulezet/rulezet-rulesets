rule TTP_XOR_MULT_DOSStub_5553 {
  strings:
    $key_5553 = { 01 3b [2] 75 23 [2] 32 21 [2] 75 30 [2] 3b 3c [2] 37 36 [2] 20 3d [2] 3b 73 [2] 06 }

  condition:
    any of them
}