rule TTP_XOR_MULT_DOSStub_a60f {
  strings:
    $key_a60f = { f2 67 [2] 86 7f [2] c1 7d [2] 86 6c [2] c8 60 [2] c4 6a [2] d3 61 [2] c8 2f [2] f5 }

  condition:
    any of them
}