rule TTP_XOR_MULT_DOSStub_b514 {
  strings:
    $key_b514 = { e1 7c [2] 95 64 [2] d2 66 [2] 95 77 [2] db 7b [2] d7 71 [2] c0 7a [2] db 34 [2] e6 }

  condition:
    any of them
}