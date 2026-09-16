rule TTP_XOR_MULT_DOSStub_2135 {
  strings:
    $key_2135 = { 75 5d [2] 01 45 [2] 46 47 [2] 01 56 [2] 4f 5a [2] 43 50 [2] 54 5b [2] 4f 15 [2] 72 }

  condition:
    any of them
}