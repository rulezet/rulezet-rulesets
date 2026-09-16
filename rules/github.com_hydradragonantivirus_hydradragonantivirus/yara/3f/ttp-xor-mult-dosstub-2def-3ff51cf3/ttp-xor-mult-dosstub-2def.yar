rule TTP_XOR_MULT_DOSStub_2def {
  strings:
    $key_2def = { 79 87 [2] 0d 9f [2] 4a 9d [2] 0d 8c [2] 43 80 [2] 4f 8a [2] 58 81 [2] 43 cf [2] 7e }

  condition:
    any of them
}