rule TTP_XOR_MULT_DOSStub_557f {
  strings:
    $key_557f = { 01 17 [2] 75 0f [2] 32 0d [2] 75 1c [2] 3b 10 [2] 37 1a [2] 20 11 [2] 3b 5f [2] 06 }

  condition:
    any of them
}