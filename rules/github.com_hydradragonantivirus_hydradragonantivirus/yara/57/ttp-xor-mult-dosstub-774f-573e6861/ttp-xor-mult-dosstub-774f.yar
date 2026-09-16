rule TTP_XOR_MULT_DOSStub_774f {
  strings:
    $key_774f = { 23 27 [2] 57 3f [2] 10 3d [2] 57 2c [2] 19 20 [2] 15 2a [2] 02 21 [2] 19 6f [2] 24 }

  condition:
    any of them
}