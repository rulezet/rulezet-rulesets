rule TTP_XOR_MULT_DOSStub_6c04 {
  strings:
    $key_6c04 = { 38 6c [2] 4c 74 [2] 0b 76 [2] 4c 67 [2] 02 6b [2] 0e 61 [2] 19 6a [2] 02 24 [2] 3f }

  condition:
    any of them
}