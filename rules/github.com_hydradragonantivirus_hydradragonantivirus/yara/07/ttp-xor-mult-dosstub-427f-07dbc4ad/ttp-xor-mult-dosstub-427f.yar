rule TTP_XOR_MULT_DOSStub_427f {
  strings:
    $key_427f = { 16 17 [2] 62 0f [2] 25 0d [2] 62 1c [2] 2c 10 [2] 20 1a [2] 37 11 [2] 2c 5f [2] 11 }

  condition:
    any of them
}