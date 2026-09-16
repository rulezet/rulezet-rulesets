rule TTP_XOR_MULT_DOSStub_047f {
  strings:
    $key_047f = { 50 17 [2] 24 0f [2] 63 0d [2] 24 1c [2] 6a 10 [2] 66 1a [2] 71 11 [2] 6a 5f [2] 57 }

  condition:
    any of them
}