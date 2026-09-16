rule TTP_XOR_MULT_DOSStub_445f {
  strings:
    $key_445f = { 10 37 [2] 64 2f [2] 23 2d [2] 64 3c [2] 2a 30 [2] 26 3a [2] 31 31 [2] 2a 7f [2] 17 }

  condition:
    any of them
}