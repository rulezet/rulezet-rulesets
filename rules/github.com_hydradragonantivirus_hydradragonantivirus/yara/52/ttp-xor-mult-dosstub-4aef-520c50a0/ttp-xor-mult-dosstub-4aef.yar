rule TTP_XOR_MULT_DOSStub_4aef {
  strings:
    $key_4aef = { 1e 87 [2] 6a 9f [2] 2d 9d [2] 6a 8c [2] 24 80 [2] 28 8a [2] 3f 81 [2] 24 cf [2] 19 }

  condition:
    any of them
}