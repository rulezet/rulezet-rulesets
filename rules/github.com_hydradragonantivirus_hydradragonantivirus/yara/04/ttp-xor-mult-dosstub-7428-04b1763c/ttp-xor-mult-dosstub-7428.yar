rule TTP_XOR_MULT_DOSStub_7428 {
  strings:
    $key_7428 = { 20 40 [2] 54 58 [2] 13 5a [2] 54 4b [2] 1a 47 [2] 16 4d [2] 01 46 [2] 1a 08 [2] 27 }

  condition:
    any of them
}