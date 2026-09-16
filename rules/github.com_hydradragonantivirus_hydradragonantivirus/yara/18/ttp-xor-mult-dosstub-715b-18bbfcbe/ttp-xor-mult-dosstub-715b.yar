rule TTP_XOR_MULT_DOSStub_715b {
  strings:
    $key_715b = { 25 33 [2] 51 2b [2] 16 29 [2] 51 38 [2] 1f 34 [2] 13 3e [2] 04 35 [2] 1f 7b [2] 22 }

  condition:
    any of them
}