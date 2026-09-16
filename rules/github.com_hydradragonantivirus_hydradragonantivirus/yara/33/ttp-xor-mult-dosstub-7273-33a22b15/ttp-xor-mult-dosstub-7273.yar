rule TTP_XOR_MULT_DOSStub_7273 {
  strings:
    $key_7273 = { 26 1b [2] 52 03 [2] 15 01 [2] 52 10 [2] 1c 1c [2] 10 16 [2] 07 1d [2] 1c 53 [2] 21 }

  condition:
    any of them
}