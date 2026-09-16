rule TTP_XOR_MULT_DOSStub_b503 {
  strings:
    $key_b503 = { e1 6b [2] 95 73 [2] d2 71 [2] 95 60 [2] db 6c [2] d7 66 [2] c0 6d [2] db 23 [2] e6 }

  condition:
    any of them
}