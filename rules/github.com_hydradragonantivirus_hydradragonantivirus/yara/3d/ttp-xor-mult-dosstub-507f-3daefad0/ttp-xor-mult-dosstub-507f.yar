rule TTP_XOR_MULT_DOSStub_507f {
  strings:
    $key_507f = { 04 17 [2] 70 0f [2] 37 0d [2] 70 1c [2] 3e 10 [2] 32 1a [2] 25 11 [2] 3e 5f [2] 03 }

  condition:
    any of them
}