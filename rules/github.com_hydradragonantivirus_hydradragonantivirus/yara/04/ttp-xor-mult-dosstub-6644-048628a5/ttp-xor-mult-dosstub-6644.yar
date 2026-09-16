rule TTP_XOR_MULT_DOSStub_6644 {
  strings:
    $key_6644 = { 32 2c [2] 46 34 [2] 01 36 [2] 46 27 [2] 08 2b [2] 04 21 [2] 13 2a [2] 08 64 [2] 35 }

  condition:
    any of them
}