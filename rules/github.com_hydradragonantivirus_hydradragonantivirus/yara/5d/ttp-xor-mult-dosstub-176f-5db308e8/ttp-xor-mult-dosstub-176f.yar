rule TTP_XOR_MULT_DOSStub_176f {
  strings:
    $key_176f = { 43 07 [2] 37 1f [2] 70 1d [2] 37 0c [2] 79 00 [2] 75 0a [2] 62 01 [2] 79 4f [2] 44 }

  condition:
    any of them
}