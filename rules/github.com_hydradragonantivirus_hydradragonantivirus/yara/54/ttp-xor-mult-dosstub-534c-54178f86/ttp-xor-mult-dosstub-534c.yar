rule TTP_XOR_MULT_DOSStub_534c {
  strings:
    $key_534c = { 07 24 [2] 73 3c [2] 34 3e [2] 73 2f [2] 3d 23 [2] 31 29 [2] 26 22 [2] 3d 6c [2] 00 }

  condition:
    any of them
}