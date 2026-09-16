rule TTP_XOR_MULT_DOSStub_3d0b {
  strings:
    $key_3d0b = { 69 63 [2] 1d 7b [2] 5a 79 [2] 1d 68 [2] 53 64 [2] 5f 6e [2] 48 65 [2] 53 2b [2] 6e }

  condition:
    any of them
}