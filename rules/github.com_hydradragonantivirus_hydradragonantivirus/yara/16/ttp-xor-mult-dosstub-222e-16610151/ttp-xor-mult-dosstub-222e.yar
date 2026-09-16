rule TTP_XOR_MULT_DOSStub_222e {
  strings:
    $key_222e = { 76 46 [2] 02 5e [2] 45 5c [2] 02 4d [2] 4c 41 [2] 40 4b [2] 57 40 [2] 4c 0e [2] 71 }

  condition:
    any of them
}