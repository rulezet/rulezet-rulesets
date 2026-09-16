rule TTP_XOR_MULT_DOSStub_38aa {
  strings:
    $key_38aa = { 6c c2 [2] 18 da [2] 5f d8 [2] 18 c9 [2] 56 c5 [2] 5a cf [2] 4d c4 [2] 56 8a [2] 6b }

  condition:
    any of them
}