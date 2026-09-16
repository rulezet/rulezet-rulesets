rule TTP_XOR_MULT_DOSStub_1d2e {
  strings:
    $key_1d2e = { 49 46 [2] 3d 5e [2] 7a 5c [2] 3d 4d [2] 73 41 [2] 7f 4b [2] 68 40 [2] 73 0e [2] 4e }

  condition:
    any of them
}