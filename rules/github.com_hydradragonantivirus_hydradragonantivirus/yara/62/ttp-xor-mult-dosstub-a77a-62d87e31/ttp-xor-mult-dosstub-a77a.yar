rule TTP_XOR_MULT_DOSStub_a77a {
  strings:
    $key_a77a = { f3 12 [2] 87 0a [2] c0 08 [2] 87 19 [2] c9 15 [2] c5 1f [2] d2 14 [2] c9 5a [2] f4 }

  condition:
    any of them
}