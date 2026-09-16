rule TTP_XOR_MULT_DOSStub_25ee {
  strings:
    $key_25ee = { 71 86 [2] 05 9e [2] 42 9c [2] 05 8d [2] 4b 81 [2] 47 8b [2] 50 80 [2] 4b ce [2] 76 }

  condition:
    any of them
}