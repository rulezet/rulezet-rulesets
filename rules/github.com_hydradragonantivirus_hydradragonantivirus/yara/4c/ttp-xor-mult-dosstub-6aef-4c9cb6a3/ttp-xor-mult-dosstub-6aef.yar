rule TTP_XOR_MULT_DOSStub_6aef {
  strings:
    $key_6aef = { 3e 87 [2] 4a 9f [2] 0d 9d [2] 4a 8c [2] 04 80 [2] 08 8a [2] 1f 81 [2] 04 cf [2] 39 }

  condition:
    any of them
}