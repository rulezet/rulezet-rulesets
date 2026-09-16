rule TTP_XOR_MULT_DOSStub_265f {
  strings:
    $key_265f = { 72 37 [2] 06 2f [2] 41 2d [2] 06 3c [2] 48 30 [2] 44 3a [2] 53 31 [2] 48 7f [2] 75 }

  condition:
    any of them
}