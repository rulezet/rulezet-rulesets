rule TTP_XOR_MULT_DOSStub_53ec {
  strings:
    $key_53ec = { 07 84 [2] 73 9c [2] 34 9e [2] 73 8f [2] 3d 83 [2] 31 89 [2] 26 82 [2] 3d cc [2] 00 }

  condition:
    any of them
}