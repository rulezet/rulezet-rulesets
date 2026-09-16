rule TTP_XOR_MULT_DOSStub_6664 {
  strings:
    $key_6664 = { 32 0c [2] 46 14 [2] 01 16 [2] 46 07 [2] 08 0b [2] 04 01 [2] 13 0a [2] 08 44 [2] 35 }

  condition:
    any of them
}