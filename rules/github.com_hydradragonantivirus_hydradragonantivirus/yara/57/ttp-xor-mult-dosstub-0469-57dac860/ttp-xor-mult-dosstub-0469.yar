rule TTP_XOR_MULT_DOSStub_0469 {
  strings:
    $key_0469 = { 50 01 [2] 24 19 [2] 63 1b [2] 24 0a [2] 6a 06 [2] 66 0c [2] 71 07 [2] 6a 49 [2] 57 }

  condition:
    any of them
}