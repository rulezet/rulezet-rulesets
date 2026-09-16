rule TTP_XOR_MULT_DOSStub_530e {
  strings:
    $key_530e = { 07 66 [2] 73 7e [2] 34 7c [2] 73 6d [2] 3d 61 [2] 31 6b [2] 26 60 [2] 3d 2e [2] 00 }

  condition:
    any of them
}