rule TTP_XOR_MULT_DOSStub_5228 {
  strings:
    $key_5228 = { 06 40 [2] 72 58 [2] 35 5a [2] 72 4b [2] 3c 47 [2] 30 4d [2] 27 46 [2] 3c 08 [2] 01 }

  condition:
    any of them
}