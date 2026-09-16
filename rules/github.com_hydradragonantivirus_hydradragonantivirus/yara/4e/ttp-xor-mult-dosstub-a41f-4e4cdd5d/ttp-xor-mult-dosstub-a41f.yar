rule TTP_XOR_MULT_DOSStub_a41f {
  strings:
    $key_a41f = { f0 77 [2] 84 6f [2] c3 6d [2] 84 7c [2] ca 70 [2] c6 7a [2] d1 71 [2] ca 3f [2] f7 }

  condition:
    any of them
}