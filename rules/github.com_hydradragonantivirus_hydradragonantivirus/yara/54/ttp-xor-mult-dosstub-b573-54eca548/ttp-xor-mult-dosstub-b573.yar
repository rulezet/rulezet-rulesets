rule TTP_XOR_MULT_DOSStub_b573 {
  strings:
    $key_b573 = { e1 1b [2] 95 03 [2] d2 01 [2] 95 10 [2] db 1c [2] d7 16 [2] c0 1d [2] db 53 [2] e6 }

  condition:
    any of them
}