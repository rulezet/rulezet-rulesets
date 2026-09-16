rule TTP_XOR_MULT_DOSStub_11ef {
  strings:
    $key_11ef = { 45 87 [2] 31 9f [2] 76 9d [2] 31 8c [2] 7f 80 [2] 73 8a [2] 64 81 [2] 7f cf [2] 42 }

  condition:
    any of them
}