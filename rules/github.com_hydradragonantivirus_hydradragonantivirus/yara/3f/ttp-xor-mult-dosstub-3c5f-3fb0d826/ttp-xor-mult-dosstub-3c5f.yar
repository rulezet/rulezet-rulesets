rule TTP_XOR_MULT_DOSStub_3c5f {
  strings:
    $key_3c5f = { 68 37 [2] 1c 2f [2] 5b 2d [2] 1c 3c [2] 52 30 [2] 5e 3a [2] 49 31 [2] 52 7f [2] 6f }

  condition:
    any of them
}