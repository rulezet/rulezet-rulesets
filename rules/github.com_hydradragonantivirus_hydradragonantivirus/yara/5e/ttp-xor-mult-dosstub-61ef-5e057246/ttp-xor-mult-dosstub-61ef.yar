rule TTP_XOR_MULT_DOSStub_61ef {
  strings:
    $key_61ef = { 35 87 [2] 41 9f [2] 06 9d [2] 41 8c [2] 0f 80 [2] 03 8a [2] 14 81 [2] 0f cf [2] 32 }

  condition:
    any of them
}