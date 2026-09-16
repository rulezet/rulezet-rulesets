rule TTP_XOR_MULT_DOSStub_656f {
  strings:
    $key_656f = { 31 07 [2] 45 1f [2] 02 1d [2] 45 0c [2] 0b 00 [2] 07 0a [2] 10 01 [2] 0b 4f [2] 36 }

  condition:
    any of them
}