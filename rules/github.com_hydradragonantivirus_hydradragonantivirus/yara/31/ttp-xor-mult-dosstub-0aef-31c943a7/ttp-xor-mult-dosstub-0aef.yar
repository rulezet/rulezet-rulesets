rule TTP_XOR_MULT_DOSStub_0aef {
  strings:
    $key_0aef = { 5e 87 [2] 2a 9f [2] 6d 9d [2] 2a 8c [2] 64 80 [2] 68 8a [2] 7f 81 [2] 64 cf [2] 59 }

  condition:
    any of them
}