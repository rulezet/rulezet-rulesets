rule TTP_XOR_MULT_DOSStub_b502 {
  strings:
    $key_b502 = { e1 6a [2] 95 72 [2] d2 70 [2] 95 61 [2] db 6d [2] d7 67 [2] c0 6c [2] db 22 [2] e6 }

  condition:
    any of them
}