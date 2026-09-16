rule TTP_XOR_MULT_DOSStub_467f {
  strings:
    $key_467f = { 12 17 [2] 66 0f [2] 21 0d [2] 66 1c [2] 28 10 [2] 24 1a [2] 33 11 [2] 28 5f [2] 15 }

  condition:
    any of them
}