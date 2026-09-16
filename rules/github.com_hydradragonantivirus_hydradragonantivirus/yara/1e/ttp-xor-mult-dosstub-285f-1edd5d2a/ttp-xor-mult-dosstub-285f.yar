rule TTP_XOR_MULT_DOSStub_285f {
  strings:
    $key_285f = { 7c 37 [2] 08 2f [2] 4f 2d [2] 08 3c [2] 46 30 [2] 4a 3a [2] 5d 31 [2] 46 7f [2] 7b }

  condition:
    any of them
}