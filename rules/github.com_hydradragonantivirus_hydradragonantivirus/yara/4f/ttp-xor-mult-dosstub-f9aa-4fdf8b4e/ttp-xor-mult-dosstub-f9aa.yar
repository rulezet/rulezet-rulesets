rule TTP_XOR_MULT_DOSStub_f9aa {
  strings:
    $key_f9aa = { ad c2 [2] d9 da [2] 9e d8 [2] d9 c9 [2] 97 c5 [2] 9b cf [2] 8c c4 [2] 97 8a [2] aa }

  condition:
    any of them
}