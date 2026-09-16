rule TTP_XOR_MULT_DOSStub_6655 {
  strings:
    $key_6655 = { 32 3d [2] 46 25 [2] 01 27 [2] 46 36 [2] 08 3a [2] 04 30 [2] 13 3b [2] 08 75 [2] 35 }

  condition:
    any of them
}