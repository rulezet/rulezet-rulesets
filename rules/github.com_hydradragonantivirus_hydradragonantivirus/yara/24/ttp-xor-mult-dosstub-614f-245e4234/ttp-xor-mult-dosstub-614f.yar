rule TTP_XOR_MULT_DOSStub_614f {
  strings:
    $key_614f = { 35 27 [2] 41 3f [2] 06 3d [2] 41 2c [2] 0f 20 [2] 03 2a [2] 14 21 [2] 0f 6f [2] 32 }

  condition:
    any of them
}