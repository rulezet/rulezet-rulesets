rule TTP_XOR_MULT_DOSStub_2ee9 {
  strings:
    $key_2ee9 = { 7a 81 [2] 0e 99 [2] 49 9b [2] 0e 8a [2] 40 86 [2] 4c 8c [2] 5b 87 [2] 40 c9 [2] 7d }

  condition:
    any of them
}