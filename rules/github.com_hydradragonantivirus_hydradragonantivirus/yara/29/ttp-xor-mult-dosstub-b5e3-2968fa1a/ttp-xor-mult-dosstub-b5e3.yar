rule TTP_XOR_MULT_DOSStub_b5e3 {
  strings:
    $key_b5e3 = { e1 8b [2] 95 93 [2] d2 91 [2] 95 80 [2] db 8c [2] d7 86 [2] c0 8d [2] db c3 [2] e6 }

  condition:
    any of them
}