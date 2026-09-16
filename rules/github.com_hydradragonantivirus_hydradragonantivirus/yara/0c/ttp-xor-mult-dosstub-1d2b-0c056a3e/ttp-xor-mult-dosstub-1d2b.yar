rule TTP_XOR_MULT_DOSStub_1d2b {
  strings:
    $key_1d2b = { 49 43 [2] 3d 5b [2] 7a 59 [2] 3d 48 [2] 73 44 [2] 7f 4e [2] 68 45 [2] 73 0b [2] 4e }

  condition:
    any of them
}