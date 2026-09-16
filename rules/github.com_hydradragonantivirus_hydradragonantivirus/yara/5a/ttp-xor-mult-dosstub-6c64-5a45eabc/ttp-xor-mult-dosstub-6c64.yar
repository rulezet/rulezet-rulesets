rule TTP_XOR_MULT_DOSStub_6c64 {
  strings:
    $key_6c64 = { 38 0c [2] 4c 14 [2] 0b 16 [2] 4c 07 [2] 02 0b [2] 0e 01 [2] 19 0a [2] 02 44 [2] 3f }

  condition:
    any of them
}