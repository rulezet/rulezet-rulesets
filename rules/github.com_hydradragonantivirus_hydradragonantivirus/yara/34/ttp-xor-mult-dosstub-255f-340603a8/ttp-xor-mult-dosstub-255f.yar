rule TTP_XOR_MULT_DOSStub_255f {
  strings:
    $key_255f = { 71 37 [2] 05 2f [2] 42 2d [2] 05 3c [2] 4b 30 [2] 47 3a [2] 50 31 [2] 4b 7f [2] 76 }

  condition:
    any of them
}