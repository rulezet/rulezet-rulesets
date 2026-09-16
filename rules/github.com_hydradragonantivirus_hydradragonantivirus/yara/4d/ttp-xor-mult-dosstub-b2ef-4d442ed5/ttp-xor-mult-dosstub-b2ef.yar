rule TTP_XOR_MULT_DOSStub_b2ef {
  strings:
    $key_b2ef = { e6 87 [2] 92 9f [2] d5 9d [2] 92 8c [2] dc 80 [2] d0 8a [2] c7 81 [2] dc cf [2] e1 }

  condition:
    any of them
}