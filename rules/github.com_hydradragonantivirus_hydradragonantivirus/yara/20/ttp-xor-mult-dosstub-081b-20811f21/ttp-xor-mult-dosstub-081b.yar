rule TTP_XOR_MULT_DOSStub_081b {
  strings:
    $key_081b = { 5c 73 [2] 28 6b [2] 6f 69 [2] 28 78 [2] 66 74 [2] 6a 7e [2] 7d 75 [2] 66 3b [2] 5b }

  condition:
    any of them
}