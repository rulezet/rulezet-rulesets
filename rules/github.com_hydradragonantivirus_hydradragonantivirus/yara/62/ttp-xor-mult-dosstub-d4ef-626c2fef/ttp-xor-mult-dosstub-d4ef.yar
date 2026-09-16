rule TTP_XOR_MULT_DOSStub_d4ef {
  strings:
    $key_d4ef = { 80 87 [2] f4 9f [2] b3 9d [2] f4 8c [2] ba 80 [2] b6 8a [2] a1 81 [2] ba cf [2] 87 }

  condition:
    any of them
}