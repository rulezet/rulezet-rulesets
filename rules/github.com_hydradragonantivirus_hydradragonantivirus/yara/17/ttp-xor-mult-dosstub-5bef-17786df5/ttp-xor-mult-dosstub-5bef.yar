rule TTP_XOR_MULT_DOSStub_5bef {
  strings:
    $key_5bef = { 0f 87 [2] 7b 9f [2] 3c 9d [2] 7b 8c [2] 35 80 [2] 39 8a [2] 2e 81 [2] 35 cf [2] 08 }

  condition:
    any of them
}