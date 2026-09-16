rule TTP_XOR_MULT_DOSStub_1fef {
  strings:
    $key_1fef = { 4b 87 [2] 3f 9f [2] 78 9d [2] 3f 8c [2] 71 80 [2] 7d 8a [2] 6a 81 [2] 71 cf [2] 4c }

  condition:
    any of them
}