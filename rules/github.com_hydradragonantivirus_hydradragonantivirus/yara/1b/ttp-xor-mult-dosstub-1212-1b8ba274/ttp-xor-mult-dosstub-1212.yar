rule TTP_XOR_MULT_DOSStub_1212 {
  strings:
    $key_1212 = { 46 7a [2] 32 62 [2] 75 60 [2] 32 71 [2] 7c 7d [2] 70 77 [2] 67 7c [2] 7c 32 [2] 41 }

  condition:
    any of them
}