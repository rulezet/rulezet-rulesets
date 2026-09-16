rule TTP_XOR_MULT_DOSStub_515b {
  strings:
    $key_515b = { 05 33 [2] 71 2b [2] 36 29 [2] 71 38 [2] 3f 34 [2] 33 3e [2] 24 35 [2] 3f 7b [2] 02 }

  condition:
    any of them
}