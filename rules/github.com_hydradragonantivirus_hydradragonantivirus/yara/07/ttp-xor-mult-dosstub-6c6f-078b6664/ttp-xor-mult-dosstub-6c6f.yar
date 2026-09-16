rule TTP_XOR_MULT_DOSStub_6c6f {
  strings:
    $key_6c6f = { 38 07 [2] 4c 1f [2] 0b 1d [2] 4c 0c [2] 02 00 [2] 0e 0a [2] 19 01 [2] 02 4f [2] 3f }

  condition:
    any of them
}