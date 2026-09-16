rule TTP_XOR_MULT_DOSStub_6b42 {
  strings:
    $key_6b42 = { 3f 2a [2] 4b 32 [2] 0c 30 [2] 4b 21 [2] 05 2d [2] 09 27 [2] 1e 2c [2] 05 62 [2] 38 }

  condition:
    any of them
}