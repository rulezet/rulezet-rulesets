rule TTP_XOR_MULT_DOSStub_87ee {
  strings:
    $key_87ee = { d3 86 [2] a7 9e [2] e0 9c [2] a7 8d [2] e9 81 [2] e5 8b [2] f2 80 [2] e9 ce [2] d4 }

  condition:
    any of them
}