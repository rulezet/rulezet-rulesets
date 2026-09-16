rule TTP_XOR_MULT_DOSStub_19aa {
  strings:
    $key_19aa = { 4d c2 [2] 39 da [2] 7e d8 [2] 39 c9 [2] 77 c5 [2] 7b cf [2] 6c c4 [2] 77 8a [2] 4a }

  condition:
    any of them
}