rule TTP_XOR_MULT_DOSStub_a12f {
  strings:
    $key_a12f = { f5 47 [2] 81 5f [2] c6 5d [2] 81 4c [2] cf 40 [2] c3 4a [2] d4 41 [2] cf 0f [2] f2 }

  condition:
    any of them
}