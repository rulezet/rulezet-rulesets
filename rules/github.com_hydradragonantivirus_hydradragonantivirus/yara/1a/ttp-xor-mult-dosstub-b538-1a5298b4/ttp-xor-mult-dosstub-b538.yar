rule TTP_XOR_MULT_DOSStub_b538 {
  strings:
    $key_b538 = { e1 50 [2] 95 48 [2] d2 4a [2] 95 5b [2] db 57 [2] d7 5d [2] c0 56 [2] db 18 [2] e6 }

  condition:
    any of them
}