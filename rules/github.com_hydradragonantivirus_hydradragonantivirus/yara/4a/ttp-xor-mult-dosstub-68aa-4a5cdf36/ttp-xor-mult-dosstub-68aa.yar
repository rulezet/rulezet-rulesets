rule TTP_XOR_MULT_DOSStub_68aa {
  strings:
    $key_68aa = { 3c c2 [2] 48 da [2] 0f d8 [2] 48 c9 [2] 06 c5 [2] 0a cf [2] 1d c4 [2] 06 8a [2] 3b }

  condition:
    any of them
}