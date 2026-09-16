rule TTP_XOR_MULT_DOSStub_125f {
  strings:
    $key_125f = { 46 37 [2] 32 2f [2] 75 2d [2] 32 3c [2] 7c 30 [2] 70 3a [2] 67 31 [2] 7c 7f [2] 41 }

  condition:
    any of them
}