rule TTP_XOR_MULT_DOSStub_4c64 {
  strings:
    $key_4c64 = { 18 0c [2] 6c 14 [2] 2b 16 [2] 6c 07 [2] 22 0b [2] 2e 01 [2] 39 0a [2] 22 44 [2] 1f }

  condition:
    any of them
}