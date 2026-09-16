rule TTP_XOR_MULT_DOSStub_6c74 {
  strings:
    $key_6c74 = { 38 1c [2] 4c 04 [2] 0b 06 [2] 4c 17 [2] 02 1b [2] 0e 11 [2] 19 1a [2] 02 54 [2] 3f }

  condition:
    any of them
}