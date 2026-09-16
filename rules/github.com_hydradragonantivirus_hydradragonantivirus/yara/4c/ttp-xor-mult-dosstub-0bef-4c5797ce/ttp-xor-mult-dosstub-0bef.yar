rule TTP_XOR_MULT_DOSStub_0bef {
  strings:
    $key_0bef = { 5f 87 [2] 2b 9f [2] 6c 9d [2] 2b 8c [2] 65 80 [2] 69 8a [2] 7e 81 [2] 65 cf [2] 58 }

  condition:
    any of them
}