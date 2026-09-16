rule TTP_XOR_MULT_DOSStub_53e3 {
  strings:
    $key_53e3 = { 07 8b [2] 73 93 [2] 34 91 [2] 73 80 [2] 3d 8c [2] 31 86 [2] 26 8d [2] 3d c3 [2] 00 }

  condition:
    any of them
}