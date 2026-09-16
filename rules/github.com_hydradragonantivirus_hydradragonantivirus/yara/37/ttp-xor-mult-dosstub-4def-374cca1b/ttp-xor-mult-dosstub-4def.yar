rule TTP_XOR_MULT_DOSStub_4def {
  strings:
    $key_4def = { 19 87 [2] 6d 9f [2] 2a 9d [2] 6d 8c [2] 23 80 [2] 2f 8a [2] 38 81 [2] 23 cf [2] 1e }

  condition:
    any of them
}