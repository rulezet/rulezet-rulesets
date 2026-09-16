rule TTP_XOR_MULT_DOSStub_b22c {
  strings:
    $key_b22c = { e6 44 [2] 92 5c [2] d5 5e [2] 92 4f [2] dc 43 [2] d0 49 [2] c7 42 [2] dc 0c [2] e1 }

  condition:
    any of them
}