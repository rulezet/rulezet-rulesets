rule TTP_XOR_MULT_DOSStub_4cf3 {
  strings:
    $key_4cf3 = { 18 9b [2] 6c 83 [2] 2b 81 [2] 6c 90 [2] 22 9c [2] 2e 96 [2] 39 9d [2] 22 d3 [2] 1f }

  condition:
    any of them
}