rule TTP_XOR_MULT_DOSStub_e8ef {
  strings:
    $key_e8ef = { bc 87 [2] c8 9f [2] 8f 9d [2] c8 8c [2] 86 80 [2] 8a 8a [2] 9d 81 [2] 86 cf [2] bb }

  condition:
    any of them
}