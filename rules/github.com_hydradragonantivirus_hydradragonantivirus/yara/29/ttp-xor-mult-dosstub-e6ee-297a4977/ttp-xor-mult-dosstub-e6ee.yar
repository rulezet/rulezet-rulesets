rule TTP_XOR_MULT_DOSStub_e6ee {
  strings:
    $key_e6ee = { b2 86 [2] c6 9e [2] 81 9c [2] c6 8d [2] 88 81 [2] 84 8b [2] 93 80 [2] 88 ce [2] b5 }

  condition:
    any of them
}