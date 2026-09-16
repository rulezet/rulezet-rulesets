rule TTP_XOR_MULT_DOSStub_511b {
  strings:
    $key_511b = { 05 73 [2] 71 6b [2] 36 69 [2] 71 78 [2] 3f 74 [2] 33 7e [2] 24 75 [2] 3f 3b [2] 02 }

  condition:
    any of them
}