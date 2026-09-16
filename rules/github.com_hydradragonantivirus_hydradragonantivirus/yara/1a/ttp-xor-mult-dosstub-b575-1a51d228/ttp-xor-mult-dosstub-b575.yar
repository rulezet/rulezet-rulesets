rule TTP_XOR_MULT_DOSStub_b575 {
  strings:
    $key_b575 = { e1 1d [2] 95 05 [2] d2 07 [2] 95 16 [2] db 1a [2] d7 10 [2] c0 1b [2] db 55 [2] e6 }

  condition:
    any of them
}