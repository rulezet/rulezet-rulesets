rule TTP_XOR_MULT_DOSStub_5ee2 {
  strings:
    $key_5ee2 = { 0a 8a [2] 7e 92 [2] 39 90 [2] 7e 81 [2] 30 8d [2] 3c 87 [2] 2b 8c [2] 30 c2 [2] 0d }

  condition:
    any of them
}