rule TTP_XOR_MULT_DOSStub_256f {
  strings:
    $key_256f = { 71 07 [2] 05 1f [2] 42 1d [2] 05 0c [2] 4b 00 [2] 47 0a [2] 50 01 [2] 4b 4f [2] 76 }

  condition:
    any of them
}