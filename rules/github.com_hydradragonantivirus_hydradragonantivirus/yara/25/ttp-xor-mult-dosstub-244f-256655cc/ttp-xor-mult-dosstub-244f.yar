rule TTP_XOR_MULT_DOSStub_244f {
  strings:
    $key_244f = { 70 27 [2] 04 3f [2] 43 3d [2] 04 2c [2] 4a 20 [2] 46 2a [2] 51 21 [2] 4a 6f [2] 77 }

  condition:
    any of them
}