rule TTP_XOR_MULT_DOSStub_2ee4 {
  strings:
    $key_2ee4 = { 7a 8c [2] 0e 94 [2] 49 96 [2] 0e 87 [2] 40 8b [2] 4c 81 [2] 5b 8a [2] 40 c4 [2] 7d }

  condition:
    any of them
}