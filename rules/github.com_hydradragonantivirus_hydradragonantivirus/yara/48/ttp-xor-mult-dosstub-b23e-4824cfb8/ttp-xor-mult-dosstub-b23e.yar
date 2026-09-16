rule TTP_XOR_MULT_DOSStub_b23e {
  strings:
    $key_b23e = { e6 56 [2] 92 4e [2] d5 4c [2] 92 5d [2] dc 51 [2] d0 5b [2] c7 50 [2] dc 1e [2] e1 }

  condition:
    any of them
}