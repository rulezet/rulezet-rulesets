rule TTP_XOR_MULT_DOSStub_1d1e {
  strings:
    $key_1d1e = { 49 76 [2] 3d 6e [2] 7a 6c [2] 3d 7d [2] 73 71 [2] 7f 7b [2] 68 70 [2] 73 3e [2] 4e }

  condition:
    any of them
}