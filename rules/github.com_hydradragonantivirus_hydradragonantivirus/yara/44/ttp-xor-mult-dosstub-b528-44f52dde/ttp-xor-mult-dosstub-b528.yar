rule TTP_XOR_MULT_DOSStub_b528 {
  strings:
    $key_b528 = { e1 40 [2] 95 58 [2] d2 5a [2] 95 4b [2] db 47 [2] d7 4d [2] c0 46 [2] db 08 [2] e6 }

  condition:
    any of them
}