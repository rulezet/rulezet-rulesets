rule TTP_XOR_MULT_DOSStub_53ee {
  strings:
    $key_53ee = { 07 86 [2] 73 9e [2] 34 9c [2] 73 8d [2] 3d 81 [2] 31 8b [2] 26 80 [2] 3d ce [2] 00 }

  condition:
    any of them
}