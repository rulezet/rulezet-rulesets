rule TTP_XOR_MULT_DOSStub_20ef {
  strings:
    $key_20ef = { 74 87 [2] 00 9f [2] 47 9d [2] 00 8c [2] 4e 80 [2] 42 8a [2] 55 81 [2] 4e cf [2] 73 }

  condition:
    any of them
}