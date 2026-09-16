rule TTP_XOR_MULT_DOSStub_a46f {
  strings:
    $key_a46f = { f0 07 [2] 84 1f [2] c3 1d [2] 84 0c [2] ca 00 [2] c6 0a [2] d1 01 [2] ca 4f [2] f7 }

  condition:
    any of them
}