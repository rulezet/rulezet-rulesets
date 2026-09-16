rule TTP_XOR_MULT_DOSStub_2112 {
  strings:
    $key_2112 = { 75 7a [2] 01 62 [2] 46 60 [2] 01 71 [2] 4f 7d [2] 43 77 [2] 54 7c [2] 4f 32 [2] 72 }

  condition:
    any of them
}