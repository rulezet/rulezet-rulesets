rule TTP_XOR_MULT_DOSStub_514b {
  strings:
    $key_514b = { 05 23 [2] 71 3b [2] 36 39 [2] 71 28 [2] 3f 24 [2] 33 2e [2] 24 25 [2] 3f 6b [2] 02 }

  condition:
    any of them
}