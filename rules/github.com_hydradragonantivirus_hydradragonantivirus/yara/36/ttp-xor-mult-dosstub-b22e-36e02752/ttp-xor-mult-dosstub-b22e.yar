rule TTP_XOR_MULT_DOSStub_b22e {
  strings:
    $key_b22e = { e6 46 [2] 92 5e [2] d5 5c [2] 92 4d [2] dc 41 [2] d0 4b [2] c7 40 [2] dc 0e [2] e1 }

  condition:
    any of them
}