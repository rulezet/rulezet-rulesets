rule TTP_XOR_MULT_DOSStub_71ef {
  strings:
    $key_71ef = { 25 87 [2] 51 9f [2] 16 9d [2] 51 8c [2] 1f 80 [2] 13 8a [2] 04 81 [2] 1f cf [2] 22 }

  condition:
    any of them
}