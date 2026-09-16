rule TTP_XOR_MULT_DOSStub_6652 {
  strings:
    $key_6652 = { 32 3a [2] 46 22 [2] 01 20 [2] 46 31 [2] 08 3d [2] 04 37 [2] 13 3c [2] 08 72 [2] 35 }

  condition:
    any of them
}