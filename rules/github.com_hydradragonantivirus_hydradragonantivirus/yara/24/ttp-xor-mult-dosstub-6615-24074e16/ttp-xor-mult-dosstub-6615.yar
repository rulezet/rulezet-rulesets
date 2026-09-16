rule TTP_XOR_MULT_DOSStub_6615 {
  strings:
    $key_6615 = { 32 7d [2] 46 65 [2] 01 67 [2] 46 76 [2] 08 7a [2] 04 70 [2] 13 7b [2] 08 35 [2] 35 }

  condition:
    any of them
}