rule TTP_XOR_MULT_DOSStub_407f {
  strings:
    $key_407f = { 14 17 [2] 60 0f [2] 27 0d [2] 60 1c [2] 2e 10 [2] 22 1a [2] 35 11 [2] 2e 5f [2] 13 }

  condition:
    any of them
}