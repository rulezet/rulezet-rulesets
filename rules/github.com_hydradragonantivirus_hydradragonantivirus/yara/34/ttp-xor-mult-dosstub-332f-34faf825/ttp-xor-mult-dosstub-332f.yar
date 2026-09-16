rule TTP_XOR_MULT_DOSStub_332f {
  strings:
    $key_332f = { 67 47 [2] 13 5f [2] 54 5d [2] 13 4c [2] 5d 40 [2] 51 4a [2] 46 41 [2] 5d 0f [2] 60 }

  condition:
    any of them
}