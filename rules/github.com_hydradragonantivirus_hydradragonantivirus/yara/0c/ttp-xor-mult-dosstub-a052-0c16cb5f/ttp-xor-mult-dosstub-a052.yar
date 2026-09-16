rule TTP_XOR_MULT_DOSStub_a052 {
  strings:
    $key_a052 = { f4 3a [2] 80 22 [2] c7 20 [2] 80 31 [2] ce 3d [2] c2 37 [2] d5 3c [2] ce 72 [2] f3 }

  condition:
    any of them
}