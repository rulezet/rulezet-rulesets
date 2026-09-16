rule TTP_XOR_MULT_DOSStub_c6ef {
  strings:
    $key_c6ef = { 92 87 [2] e6 9f [2] a1 9d [2] e6 8c [2] a8 80 [2] a4 8a [2] b3 81 [2] a8 cf [2] 95 }

  condition:
    any of them
}