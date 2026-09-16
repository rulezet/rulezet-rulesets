rule TTP_XOR_MULT_DOSStub_221b {
  strings:
    $key_221b = { 76 73 [2] 02 6b [2] 45 69 [2] 02 78 [2] 4c 74 [2] 40 7e [2] 57 75 [2] 4c 3b [2] 71 }

  condition:
    any of them
}