rule TTP_XOR_MULT_DOSStub_243e {
  strings:
    $key_243e = { 70 56 [2] 04 4e [2] 43 4c [2] 04 5d [2] 4a 51 [2] 46 5b [2] 51 50 [2] 4a 1e [2] 77 }

  condition:
    any of them
}