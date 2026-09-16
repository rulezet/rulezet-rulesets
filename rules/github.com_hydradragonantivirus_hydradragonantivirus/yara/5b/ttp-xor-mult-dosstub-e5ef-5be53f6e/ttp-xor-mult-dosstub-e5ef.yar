rule TTP_XOR_MULT_DOSStub_e5ef {
  strings:
    $key_e5ef = { b1 87 [2] c5 9f [2] 82 9d [2] c5 8c [2] 8b 80 [2] 87 8a [2] 90 81 [2] 8b cf [2] b6 }

  condition:
    any of them
}