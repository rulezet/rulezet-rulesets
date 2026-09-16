rule TTP_XOR_MULT_DOSStub_a47f {
  strings:
    $key_a47f = { f0 17 [2] 84 0f [2] c3 0d [2] 84 1c [2] ca 10 [2] c6 1a [2] d1 11 [2] ca 5f [2] f7 }

  condition:
    any of them
}