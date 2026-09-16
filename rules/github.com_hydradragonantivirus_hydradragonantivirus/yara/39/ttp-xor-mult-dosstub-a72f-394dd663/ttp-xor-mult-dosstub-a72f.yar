rule TTP_XOR_MULT_DOSStub_a72f {
  strings:
    $key_a72f = { f3 47 [2] 87 5f [2] c0 5d [2] 87 4c [2] c9 40 [2] c5 4a [2] d2 41 [2] c9 0f [2] f4 }

  condition:
    any of them
}