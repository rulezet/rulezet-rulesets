rule TTP_XOR_MULT_DOSStub_2ee2 {
  strings:
    $key_2ee2 = { 7a 8a [2] 0e 92 [2] 49 90 [2] 0e 81 [2] 40 8d [2] 4c 87 [2] 5b 8c [2] 40 c2 [2] 7d }

  condition:
    any of them
}