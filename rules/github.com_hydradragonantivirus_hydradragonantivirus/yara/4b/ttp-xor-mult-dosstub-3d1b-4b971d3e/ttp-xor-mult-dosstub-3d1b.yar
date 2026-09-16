rule TTP_XOR_MULT_DOSStub_3d1b {
  strings:
    $key_3d1b = { 69 73 [2] 1d 6b [2] 5a 69 [2] 1d 78 [2] 53 74 [2] 5f 7e [2] 48 75 [2] 53 3b [2] 6e }

  condition:
    any of them
}