rule TTP_XOR_MULT_DOSStub_5aef {
  strings:
    $key_5aef = { 0e 87 [2] 7a 9f [2] 3d 9d [2] 7a 8c [2] 34 80 [2] 38 8a [2] 2f 81 [2] 34 cf [2] 09 }

  condition:
    any of them
}