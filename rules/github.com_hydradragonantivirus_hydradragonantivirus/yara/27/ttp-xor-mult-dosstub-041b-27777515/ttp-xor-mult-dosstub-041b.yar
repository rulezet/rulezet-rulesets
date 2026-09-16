rule TTP_XOR_MULT_DOSStub_041b {
  strings:
    $key_041b = { 50 73 [2] 24 6b [2] 63 69 [2] 24 78 [2] 6a 74 [2] 66 7e [2] 71 75 [2] 6a 3b [2] 57 }

  condition:
    any of them
}