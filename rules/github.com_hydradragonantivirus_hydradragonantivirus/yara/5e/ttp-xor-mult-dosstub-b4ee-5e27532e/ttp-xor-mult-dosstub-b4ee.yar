rule TTP_XOR_MULT_DOSStub_b4ee {
  strings:
    $key_b4ee = { e0 86 [2] 94 9e [2] d3 9c [2] 94 8d [2] da 81 [2] d6 8b [2] c1 80 [2] da ce [2] e7 }

  condition:
    any of them
}