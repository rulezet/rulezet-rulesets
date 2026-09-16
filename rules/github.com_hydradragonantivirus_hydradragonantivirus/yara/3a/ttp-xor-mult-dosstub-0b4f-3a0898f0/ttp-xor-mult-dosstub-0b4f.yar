rule TTP_XOR_MULT_DOSStub_0b4f {
  strings:
    $key_0b4f = { 5f 27 [2] 2b 3f [2] 6c 3d [2] 2b 2c [2] 65 20 [2] 69 2a [2] 7e 21 [2] 65 6f [2] 58 }

  condition:
    any of them
}