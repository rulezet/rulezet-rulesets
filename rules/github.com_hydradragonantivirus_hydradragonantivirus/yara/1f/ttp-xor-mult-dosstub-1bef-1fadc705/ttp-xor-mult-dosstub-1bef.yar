rule TTP_XOR_MULT_DOSStub_1bef {
  strings:
    $key_1bef = { 4f 87 [2] 3b 9f [2] 7c 9d [2] 3b 8c [2] 75 80 [2] 79 8a [2] 6e 81 [2] 75 cf [2] 48 }

  condition:
    any of them
}