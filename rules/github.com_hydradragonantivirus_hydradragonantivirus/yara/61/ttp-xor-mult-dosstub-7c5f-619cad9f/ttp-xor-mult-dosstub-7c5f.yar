rule TTP_XOR_MULT_DOSStub_7c5f {
  strings:
    $key_7c5f = { 28 37 [2] 5c 2f [2] 1b 2d [2] 5c 3c [2] 12 30 [2] 1e 3a [2] 09 31 [2] 12 7f [2] 2f }

  condition:
    any of them
}