rule TTP_XOR_MULT_DOSStub_c7ef {
  strings:
    $key_c7ef = { 93 87 [2] e7 9f [2] a0 9d [2] e7 8c [2] a9 80 [2] a5 8a [2] b2 81 [2] a9 cf [2] 94 }

  condition:
    any of them
}