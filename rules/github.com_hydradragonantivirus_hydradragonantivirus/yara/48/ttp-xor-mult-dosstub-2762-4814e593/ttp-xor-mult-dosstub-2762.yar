rule TTP_XOR_MULT_DOSStub_2762 {
  strings:
    $key_2762 = { 73 0a [2] 07 12 [2] 40 10 [2] 07 01 [2] 49 0d [2] 45 07 [2] 52 0c [2] 49 42 [2] 74 }

  condition:
    any of them
}