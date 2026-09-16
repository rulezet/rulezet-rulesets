rule TTP_XOR_MULT_DOSStub_156f {
  strings:
    $key_156f = { 41 07 [2] 35 1f [2] 72 1d [2] 35 0c [2] 7b 00 [2] 77 0a [2] 60 01 [2] 7b 4f [2] 46 }

  condition:
    any of them
}