rule TTP_XOR_MULT_DOSStub_e6ef {
  strings:
    $key_e6ef = { b2 87 [2] c6 9f [2] 81 9d [2] c6 8c [2] 88 80 [2] 84 8a [2] 93 81 [2] 88 cf [2] b5 }

  condition:
    any of them
}