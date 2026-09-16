rule TTP_XOR_MULT_DOSStub_b74f {
  strings:
    $key_b74f = { e3 27 [2] 97 3f [2] d0 3d [2] 97 2c [2] d9 20 [2] d5 2a [2] c2 21 [2] d9 6f [2] e4 }

  condition:
    any of them
}