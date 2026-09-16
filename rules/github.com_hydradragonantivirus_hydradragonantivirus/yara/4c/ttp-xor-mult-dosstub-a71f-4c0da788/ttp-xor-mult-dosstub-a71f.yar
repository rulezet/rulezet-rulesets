rule TTP_XOR_MULT_DOSStub_a71f {
  strings:
    $key_a71f = { f3 77 [2] 87 6f [2] c0 6d [2] 87 7c [2] c9 70 [2] c5 7a [2] d2 71 [2] c9 3f [2] f4 }

  condition:
    any of them
}