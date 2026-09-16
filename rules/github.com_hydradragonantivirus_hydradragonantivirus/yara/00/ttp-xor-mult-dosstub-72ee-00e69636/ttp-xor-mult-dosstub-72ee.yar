rule TTP_XOR_MULT_DOSStub_72ee {
  strings:
    $key_72ee = { 26 86 [2] 52 9e [2] 15 9c [2] 52 8d [2] 1c 81 [2] 10 8b [2] 07 80 [2] 1c ce [2] 21 }

  condition:
    any of them
}