rule TTP_XOR_MULT_DOSStub_4ca3 {
  strings:
    $key_4ca3 = { 18 cb [2] 6c d3 [2] 2b d1 [2] 6c c0 [2] 22 cc [2] 2e c6 [2] 39 cd [2] 22 83 [2] 1f }

  condition:
    any of them
}