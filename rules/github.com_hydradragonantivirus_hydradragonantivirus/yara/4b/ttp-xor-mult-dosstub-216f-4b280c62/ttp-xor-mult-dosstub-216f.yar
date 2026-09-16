rule TTP_XOR_MULT_DOSStub_216f {
  strings:
    $key_216f = { 75 07 [2] 01 1f [2] 46 1d [2] 01 0c [2] 4f 00 [2] 43 0a [2] 54 01 [2] 4f 4f [2] 72 }

  condition:
    any of them
}