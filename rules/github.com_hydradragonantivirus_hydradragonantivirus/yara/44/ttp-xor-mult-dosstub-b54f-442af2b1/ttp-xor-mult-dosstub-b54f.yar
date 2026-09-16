rule TTP_XOR_MULT_DOSStub_b54f {
  strings:
    $key_b54f = { e1 27 [2] 95 3f [2] d2 3d [2] 95 2c [2] db 20 [2] d7 2a [2] c0 21 [2] db 6f [2] e6 }

  condition:
    any of them
}