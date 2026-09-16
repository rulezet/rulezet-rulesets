rule TTP_XOR_MULT_DOSStub_5726 {
  strings:
    $key_5726 = { 03 4e [2] 77 56 [2] 30 54 [2] 77 45 [2] 39 49 [2] 35 43 [2] 22 48 [2] 39 06 [2] 04 }

  condition:
    any of them
}