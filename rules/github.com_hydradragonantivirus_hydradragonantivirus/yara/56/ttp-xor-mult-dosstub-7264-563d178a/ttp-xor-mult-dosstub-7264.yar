rule TTP_XOR_MULT_DOSStub_7264 {
  strings:
    $key_7264 = { 26 0c [2] 52 14 [2] 15 16 [2] 52 07 [2] 1c 0b [2] 10 01 [2] 07 0a [2] 1c 44 [2] 21 }

  condition:
    any of them
}