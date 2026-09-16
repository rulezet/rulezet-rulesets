rule TTP_XOR_MULT_DOSStub_3d1e {
  strings:
    $key_3d1e = { 69 76 [2] 1d 6e [2] 5a 6c [2] 1d 7d [2] 53 71 [2] 5f 7b [2] 48 70 [2] 53 3e [2] 6e }

  condition:
    any of them
}