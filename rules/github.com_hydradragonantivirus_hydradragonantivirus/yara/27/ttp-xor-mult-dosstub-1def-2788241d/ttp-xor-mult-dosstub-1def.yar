rule TTP_XOR_MULT_DOSStub_1def {
  strings:
    $key_1def = { 49 87 [2] 3d 9f [2] 7a 9d [2] 3d 8c [2] 73 80 [2] 7f 8a [2] 68 81 [2] 73 cf [2] 4e }

  condition:
    any of them
}