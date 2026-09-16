rule TTP_XOR_MULT_DOSStub_0eef {
  strings:
    $key_0eef = { 5a 87 [2] 2e 9f [2] 69 9d [2] 2e 8c [2] 60 80 [2] 6c 8a [2] 7b 81 [2] 60 cf [2] 5d }

  condition:
    any of them
}