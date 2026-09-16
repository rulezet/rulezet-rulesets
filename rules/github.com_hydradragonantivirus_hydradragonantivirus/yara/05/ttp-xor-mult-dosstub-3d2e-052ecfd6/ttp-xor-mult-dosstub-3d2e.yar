rule TTP_XOR_MULT_DOSStub_3d2e {
  strings:
    $key_3d2e = { 69 46 [2] 1d 5e [2] 5a 5c [2] 1d 4d [2] 53 41 [2] 5f 4b [2] 48 40 [2] 53 0e [2] 6e }

  condition:
    any of them
}