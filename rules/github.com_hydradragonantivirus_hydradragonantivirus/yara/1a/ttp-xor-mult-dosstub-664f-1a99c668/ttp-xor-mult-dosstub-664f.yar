rule TTP_XOR_MULT_DOSStub_664f {
  strings:
    $key_664f = { 32 27 [2] 46 3f [2] 01 3d [2] 46 2c [2] 08 20 [2] 04 2a [2] 13 21 [2] 08 6f [2] 35 }

  condition:
    any of them
}