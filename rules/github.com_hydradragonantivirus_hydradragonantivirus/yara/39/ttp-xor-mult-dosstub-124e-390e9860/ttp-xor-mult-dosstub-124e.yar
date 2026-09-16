rule TTP_XOR_MULT_DOSStub_124e {
  strings:
    $key_124e = { 46 26 [2] 32 3e [2] 75 3c [2] 32 2d [2] 7c 21 [2] 70 2b [2] 67 20 [2] 7c 6e [2] 41 }

  condition:
    any of them
}