rule TTP_XOR_MULT_DOSStub_b2e3 {
  strings:
    $key_b2e3 = { e6 8b [2] 92 93 [2] d5 91 [2] 92 80 [2] dc 8c [2] d0 86 [2] c7 8d [2] dc c3 [2] e1 }

  condition:
    any of them
}