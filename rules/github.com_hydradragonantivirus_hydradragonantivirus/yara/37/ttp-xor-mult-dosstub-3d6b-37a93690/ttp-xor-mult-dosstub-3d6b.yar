rule TTP_XOR_MULT_DOSStub_3d6b {
  strings:
    $key_3d6b = { 69 03 [2] 1d 1b [2] 5a 19 [2] 1d 08 [2] 53 04 [2] 5f 0e [2] 48 05 [2] 53 4b [2] 6e }

  condition:
    any of them
}