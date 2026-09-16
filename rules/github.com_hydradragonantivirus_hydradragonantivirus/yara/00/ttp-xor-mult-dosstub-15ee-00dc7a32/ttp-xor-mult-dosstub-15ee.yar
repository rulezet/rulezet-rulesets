rule TTP_XOR_MULT_DOSStub_15ee {
  strings:
    $key_15ee = { 41 86 [2] 35 9e [2] 72 9c [2] 35 8d [2] 7b 81 [2] 77 8b [2] 60 80 [2] 7b ce [2] 46 }

  condition:
    any of them
}