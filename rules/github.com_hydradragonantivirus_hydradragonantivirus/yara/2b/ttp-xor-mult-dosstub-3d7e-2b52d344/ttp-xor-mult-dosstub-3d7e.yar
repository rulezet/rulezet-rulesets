rule TTP_XOR_MULT_DOSStub_3d7e {
  strings:
    $key_3d7e = { 69 16 [2] 1d 0e [2] 5a 0c [2] 1d 1d [2] 53 11 [2] 5f 1b [2] 48 10 [2] 53 5e [2] 6e }

  condition:
    any of them
}