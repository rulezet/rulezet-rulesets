rule TTP_XOR_MULT_DOSStub_a618 {
  strings:
    $key_a618 = { f2 70 [2] 86 68 [2] c1 6a [2] 86 7b [2] c8 77 [2] c4 7d [2] d3 76 [2] c8 38 [2] f5 }

  condition:
    any of them
}