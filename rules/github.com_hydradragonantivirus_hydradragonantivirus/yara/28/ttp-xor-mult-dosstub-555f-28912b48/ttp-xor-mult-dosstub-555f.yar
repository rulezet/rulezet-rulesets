rule TTP_XOR_MULT_DOSStub_555f {
  strings:
    $key_555f = { 01 37 [2] 75 2f [2] 32 2d [2] 75 3c [2] 3b 30 [2] 37 3a [2] 20 31 [2] 3b 7f [2] 06 }

  condition:
    any of them
}