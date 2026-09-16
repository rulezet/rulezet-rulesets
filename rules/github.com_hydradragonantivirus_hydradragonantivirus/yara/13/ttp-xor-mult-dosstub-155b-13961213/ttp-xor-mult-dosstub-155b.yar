rule TTP_XOR_MULT_DOSStub_155b {
  strings:
    $key_155b = { 41 33 [2] 35 2b [2] 72 29 [2] 35 38 [2] 7b 34 [2] 77 3e [2] 60 35 [2] 7b 7b [2] 46 }

  condition:
    any of them
}