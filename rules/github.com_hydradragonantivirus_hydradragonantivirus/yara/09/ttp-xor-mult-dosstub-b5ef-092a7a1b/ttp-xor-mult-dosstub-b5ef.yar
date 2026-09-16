rule TTP_XOR_MULT_DOSStub_b5ef {
  strings:
    $key_b5ef = { e1 87 [2] 95 9f [2] d2 9d [2] 95 8c [2] db 80 [2] d7 8a [2] c0 81 [2] db cf [2] e6 }

  condition:
    any of them
}