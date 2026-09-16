rule TTP_XOR_MULT_DOSStub_68f3 {
  strings:
    $key_68f3 = { 3c 9b [2] 48 83 [2] 0f 81 [2] 48 90 [2] 06 9c [2] 0a 96 [2] 1d 9d [2] 06 d3 [2] 3b }

  condition:
    any of them
}