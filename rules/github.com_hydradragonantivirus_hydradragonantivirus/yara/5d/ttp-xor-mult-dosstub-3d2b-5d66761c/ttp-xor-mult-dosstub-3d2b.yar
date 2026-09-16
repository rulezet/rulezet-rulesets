rule TTP_XOR_MULT_DOSStub_3d2b {
  strings:
    $key_3d2b = { 69 43 [2] 1d 5b [2] 5a 59 [2] 1d 48 [2] 53 44 [2] 5f 4e [2] 48 45 [2] 53 0b [2] 6e }

  condition:
    any of them
}