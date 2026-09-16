rule TTP_XOR_MULT_DOSStub_6def {
  strings:
    $key_6def = { 39 87 [2] 4d 9f [2] 0a 9d [2] 4d 8c [2] 03 80 [2] 0f 8a [2] 18 81 [2] 03 cf [2] 3e }

  condition:
    any of them
}