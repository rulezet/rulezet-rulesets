rule TTP_XOR_MULT_DOSStub_5b4f {
  strings:
    $key_5b4f = { 0f 27 [2] 7b 3f [2] 3c 3d [2] 7b 2c [2] 35 20 [2] 39 2a [2] 2e 21 [2] 35 6f [2] 08 }

  condition:
    any of them
}