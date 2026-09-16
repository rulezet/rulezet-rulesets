rule TTP_XOR_MULT_DOSStub_6672 {
  strings:
    $key_6672 = { 32 1a [2] 46 02 [2] 01 00 [2] 46 11 [2] 08 1d [2] 04 17 [2] 13 1c [2] 08 52 [2] 35 }

  condition:
    any of them
}