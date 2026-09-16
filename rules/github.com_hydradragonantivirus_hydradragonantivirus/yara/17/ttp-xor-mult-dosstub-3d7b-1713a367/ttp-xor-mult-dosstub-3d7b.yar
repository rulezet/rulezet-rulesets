rule TTP_XOR_MULT_DOSStub_3d7b {
  strings:
    $key_3d7b = { 69 13 [2] 1d 0b [2] 5a 09 [2] 1d 18 [2] 53 14 [2] 5f 1e [2] 48 15 [2] 53 5b [2] 6e }

  condition:
    any of them
}