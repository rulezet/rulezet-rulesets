rule TTP_XOR_MULT_DOSStub_44ee {
  strings:
    $key_44ee = { 10 86 [2] 64 9e [2] 23 9c [2] 64 8d [2] 2a 81 [2] 26 8b [2] 31 80 [2] 2a ce [2] 17 }

  condition:
    any of them
}