rule TTP_XOR_MULT_DOSStub_4c79 {
  strings:
    $key_4c79 = { 18 11 [2] 6c 09 [2] 2b 0b [2] 6c 1a [2] 22 16 [2] 2e 1c [2] 39 17 [2] 22 59 [2] 1f }

  condition:
    any of them
}