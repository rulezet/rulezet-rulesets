rule TTP_XOR_MULT_DOSStub_6274 {
  strings:
    $key_6274 = { 36 1c [2] 42 04 [2] 05 06 [2] 42 17 [2] 0c 1b [2] 00 11 [2] 17 1a [2] 0c 54 [2] 31 }

  condition:
    any of them
}