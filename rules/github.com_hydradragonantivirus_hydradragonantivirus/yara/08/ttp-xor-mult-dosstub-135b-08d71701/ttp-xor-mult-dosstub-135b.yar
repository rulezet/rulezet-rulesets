rule TTP_XOR_MULT_DOSStub_135b {
  strings:
    $key_135b = { 47 33 [2] 33 2b [2] 74 29 [2] 33 38 [2] 7d 34 [2] 71 3e [2] 66 35 [2] 7d 7b [2] 40 }

  condition:
    any of them
}