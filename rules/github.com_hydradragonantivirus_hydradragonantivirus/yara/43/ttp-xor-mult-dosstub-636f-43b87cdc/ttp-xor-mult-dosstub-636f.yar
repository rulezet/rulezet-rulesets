rule TTP_XOR_MULT_DOSStub_636f {
  strings:
    $key_636f = { 37 07 [2] 43 1f [2] 04 1d [2] 43 0c [2] 0d 00 [2] 01 0a [2] 16 01 [2] 0d 4f [2] 30 }

  condition:
    any of them
}