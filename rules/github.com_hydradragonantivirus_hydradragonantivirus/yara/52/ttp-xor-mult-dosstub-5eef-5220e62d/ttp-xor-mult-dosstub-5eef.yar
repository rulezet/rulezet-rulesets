rule TTP_XOR_MULT_DOSStub_5eef {
  strings:
    $key_5eef = { 0a 87 [2] 7e 9f [2] 39 9d [2] 7e 8c [2] 30 80 [2] 3c 8a [2] 2b 81 [2] 30 cf [2] 0d }

  condition:
    any of them
}