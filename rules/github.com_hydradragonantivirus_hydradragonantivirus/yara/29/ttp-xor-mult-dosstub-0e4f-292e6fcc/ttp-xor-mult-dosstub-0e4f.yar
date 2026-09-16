rule TTP_XOR_MULT_DOSStub_0e4f {
  strings:
    $key_0e4f = { 5a 27 [2] 2e 3f [2] 69 3d [2] 2e 2c [2] 60 20 [2] 6c 2a [2] 7b 21 [2] 60 6f [2] 5d }

  condition:
    any of them
}