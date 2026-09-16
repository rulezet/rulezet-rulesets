rule TTP_XOR_MULT_DOSStub_1f5b {
  strings:
    $key_1f5b = { 4b 33 [2] 3f 2b [2] 78 29 [2] 3f 38 [2] 71 34 [2] 7d 3e [2] 6a 35 [2] 71 7b [2] 4c }

  condition:
    any of them
}