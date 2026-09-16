rule TTP_XOR_MULT_DOSStub_35ee {
  strings:
    $key_35ee = { 61 86 [2] 15 9e [2] 52 9c [2] 15 8d [2] 5b 81 [2] 57 8b [2] 40 80 [2] 5b ce [2] 66 }

  condition:
    any of them
}