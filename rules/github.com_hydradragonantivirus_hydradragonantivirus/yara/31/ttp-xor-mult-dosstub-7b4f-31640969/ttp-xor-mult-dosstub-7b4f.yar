rule TTP_XOR_MULT_DOSStub_7b4f {
  strings:
    $key_7b4f = { 2f 27 [2] 5b 3f [2] 1c 3d [2] 5b 2c [2] 15 20 [2] 19 2a [2] 0e 21 [2] 15 6f [2] 28 }

  condition:
    any of them
}