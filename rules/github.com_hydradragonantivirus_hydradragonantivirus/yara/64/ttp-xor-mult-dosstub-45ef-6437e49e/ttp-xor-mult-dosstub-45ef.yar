rule TTP_XOR_MULT_DOSStub_45ef {
  strings:
    $key_45ef = { 11 87 [2] 65 9f [2] 22 9d [2] 65 8c [2] 2b 80 [2] 27 8a [2] 30 81 [2] 2b cf [2] 16 }

  condition:
    any of them
}