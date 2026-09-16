rule TTP_XOR_MULT_DOSStub_4474 {
  strings:
    $key_4474 = { 10 1c [2] 64 04 [2] 23 06 [2] 64 17 [2] 2a 1b [2] 26 11 [2] 31 1a [2] 2a 54 [2] 17 }

  condition:
    any of them
}