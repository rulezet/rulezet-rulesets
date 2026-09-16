rule TTP_XOR_MULT_DOSStub_a76f {
  strings:
    $key_a76f = { f3 07 [2] 87 1f [2] c0 1d [2] 87 0c [2] c9 00 [2] c5 0a [2] d2 01 [2] c9 4f [2] f4 }

  condition:
    any of them
}