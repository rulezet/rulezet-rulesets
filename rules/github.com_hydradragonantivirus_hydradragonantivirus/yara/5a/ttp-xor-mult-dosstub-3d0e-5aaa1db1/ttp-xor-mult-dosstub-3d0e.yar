rule TTP_XOR_MULT_DOSStub_3d0e {
  strings:
    $key_3d0e = { 69 66 [2] 1d 7e [2] 5a 7c [2] 1d 6d [2] 53 61 [2] 5f 6b [2] 48 60 [2] 53 2e [2] 6e }

  condition:
    any of them
}