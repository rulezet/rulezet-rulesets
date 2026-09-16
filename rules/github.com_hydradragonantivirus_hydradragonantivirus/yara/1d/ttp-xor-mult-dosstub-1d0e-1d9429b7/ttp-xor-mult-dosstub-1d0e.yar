rule TTP_XOR_MULT_DOSStub_1d0e {
  strings:
    $key_1d0e = { 49 66 [2] 3d 7e [2] 7a 7c [2] 3d 6d [2] 73 61 [2] 7f 6b [2] 68 60 [2] 73 2e [2] 4e }

  condition:
    any of them
}