rule TTP_XOR_MULT_DOSStub_b22b {
  strings:
    $key_b22b = { e6 43 [2] 92 5b [2] d5 59 [2] 92 48 [2] dc 44 [2] d0 4e [2] c7 45 [2] dc 0b [2] e1 }

  condition:
    any of them
}