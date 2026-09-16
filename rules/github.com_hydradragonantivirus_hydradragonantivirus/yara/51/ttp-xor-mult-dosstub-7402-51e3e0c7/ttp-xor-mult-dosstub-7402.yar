rule TTP_XOR_MULT_DOSStub_7402 {
  strings:
    $key_7402 = { 20 6a [2] 54 72 [2] 13 70 [2] 54 61 [2] 1a 6d [2] 16 67 [2] 01 6c [2] 1a 22 [2] 27 }

  condition:
    any of them
}