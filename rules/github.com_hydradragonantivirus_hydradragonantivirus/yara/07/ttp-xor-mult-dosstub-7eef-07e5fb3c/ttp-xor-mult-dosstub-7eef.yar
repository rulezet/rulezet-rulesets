rule TTP_XOR_MULT_DOSStub_7eef {
  strings:
    $key_7eef = { 2a 87 [2] 5e 9f [2] 19 9d [2] 5e 8c [2] 10 80 [2] 1c 8a [2] 0b 81 [2] 10 cf [2] 2d }

  condition:
    any of them
}