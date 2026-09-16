rule TTP_XOR_MULT_DOSStub_406f {
  strings:
    $key_406f = { 14 07 [2] 60 1f [2] 27 1d [2] 60 0c [2] 2e 00 [2] 22 0a [2] 35 01 [2] 2e 4f [2] 13 }

  condition:
    any of them
}