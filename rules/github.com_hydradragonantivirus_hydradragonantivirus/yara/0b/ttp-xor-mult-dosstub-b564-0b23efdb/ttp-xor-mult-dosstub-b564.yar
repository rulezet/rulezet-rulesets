rule TTP_XOR_MULT_DOSStub_b564 {
  strings:
    $key_b564 = { e1 0c [2] 95 14 [2] d2 16 [2] 95 07 [2] db 0b [2] d7 01 [2] c0 0a [2] db 44 [2] e6 }

  condition:
    any of them
}