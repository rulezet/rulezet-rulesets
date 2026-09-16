rule TTP_XOR_MULT_DOSStub_b5e8 {
  strings:
    $key_b5e8 = { e1 80 [2] 95 98 [2] d2 9a [2] 95 8b [2] db 87 [2] d7 8d [2] c0 86 [2] db c8 [2] e6 }

  condition:
    any of them
}