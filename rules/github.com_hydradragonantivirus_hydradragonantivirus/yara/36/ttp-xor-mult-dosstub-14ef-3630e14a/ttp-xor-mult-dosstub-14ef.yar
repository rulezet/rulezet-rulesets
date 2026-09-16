rule TTP_XOR_MULT_DOSStub_14ef {
  strings:
    $key_14ef = { 40 87 [2] 34 9f [2] 73 9d [2] 34 8c [2] 7a 80 [2] 76 8a [2] 61 81 [2] 7a cf [2] 47 }

  condition:
    any of them
}