rule TTP_XOR_MULT_DOSStub_456f {
  strings:
    $key_456f = { 11 07 [2] 65 1f [2] 22 1d [2] 65 0c [2] 2b 00 [2] 27 0a [2] 30 01 [2] 2b 4f [2] 16 }

  condition:
    any of them
}