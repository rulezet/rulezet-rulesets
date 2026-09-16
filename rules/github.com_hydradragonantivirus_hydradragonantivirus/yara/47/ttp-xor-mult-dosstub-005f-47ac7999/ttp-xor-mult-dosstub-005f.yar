rule TTP_XOR_MULT_DOSStub_005f {
  strings:
    $key_005f = { 54 37 [2] 20 2f [2] 67 2d [2] 20 3c [2] 6e 30 [2] 62 3a [2] 75 31 [2] 6e 7f [2] 53 }

  condition:
    any of them
}