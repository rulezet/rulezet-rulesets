rule TTP_XOR_MULT_DOSStub_482e {
  strings:
    $key_482e = { 1c 46 [2] 68 5e [2] 2f 5c [2] 68 4d [2] 26 41 [2] 2a 4b [2] 3d 40 [2] 26 0e [2] 1b }

  condition:
    any of them
}