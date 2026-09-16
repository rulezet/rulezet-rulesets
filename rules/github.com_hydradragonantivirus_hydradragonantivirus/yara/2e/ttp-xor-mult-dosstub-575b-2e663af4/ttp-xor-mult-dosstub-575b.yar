rule TTP_XOR_MULT_DOSStub_575b {
  strings:
    $key_575b = { 03 33 [2] 77 2b [2] 30 29 [2] 77 38 [2] 39 34 [2] 35 3e [2] 22 35 [2] 39 7b [2] 04 }

  condition:
    any of them
}