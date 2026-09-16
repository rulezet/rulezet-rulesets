rule TTP_XOR_MULT_DOSStub_2178 {
  strings:
    $key_2178 = { 75 10 [2] 01 08 [2] 46 0a [2] 01 1b [2] 4f 17 [2] 43 1d [2] 54 16 [2] 4f 58 [2] 72 }

  condition:
    any of them
}