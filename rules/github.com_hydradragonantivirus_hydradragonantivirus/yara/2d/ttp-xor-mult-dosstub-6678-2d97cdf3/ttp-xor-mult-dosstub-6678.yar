rule TTP_XOR_MULT_DOSStub_6678 {
  strings:
    $key_6678 = { 32 10 [2] 46 08 [2] 01 0a [2] 46 1b [2] 08 17 [2] 04 1d [2] 13 16 [2] 08 58 [2] 35 }

  condition:
    any of them
}