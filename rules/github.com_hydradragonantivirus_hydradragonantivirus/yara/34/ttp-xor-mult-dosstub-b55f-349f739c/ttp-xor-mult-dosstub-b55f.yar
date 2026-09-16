rule TTP_XOR_MULT_DOSStub_b55f {
  strings:
    $key_b55f = { e1 37 [2] 95 2f [2] d2 2d [2] 95 3c [2] db 30 [2] d7 3a [2] c0 31 [2] db 7f [2] e6 }

  condition:
    any of them
}