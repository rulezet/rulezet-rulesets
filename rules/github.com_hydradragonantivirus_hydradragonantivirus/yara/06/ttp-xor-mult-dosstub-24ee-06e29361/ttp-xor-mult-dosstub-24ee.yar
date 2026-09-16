rule TTP_XOR_MULT_DOSStub_24ee {
  strings:
    $key_24ee = { 70 86 [2] 04 9e [2] 43 9c [2] 04 8d [2] 4a 81 [2] 46 8b [2] 51 80 [2] 4a ce [2] 77 }

  condition:
    any of them
}