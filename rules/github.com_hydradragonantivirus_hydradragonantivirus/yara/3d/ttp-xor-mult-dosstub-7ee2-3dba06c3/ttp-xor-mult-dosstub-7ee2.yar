rule TTP_XOR_MULT_DOSStub_7ee2 {
  strings:
    $key_7ee2 = { 2a 8a [2] 5e 92 [2] 19 90 [2] 5e 81 [2] 10 8d [2] 1c 87 [2] 0b 8c [2] 10 c2 [2] 2d }

  condition:
    any of them
}