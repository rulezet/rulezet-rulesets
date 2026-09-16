rule TTP_XOR_MULT_DOSStub_357f {
  strings:
    $key_357f = { 61 17 [2] 15 0f [2] 52 0d [2] 15 1c [2] 5b 10 [2] 57 1a [2] 40 11 [2] 5b 5f [2] 66 }

  condition:
    any of them
}