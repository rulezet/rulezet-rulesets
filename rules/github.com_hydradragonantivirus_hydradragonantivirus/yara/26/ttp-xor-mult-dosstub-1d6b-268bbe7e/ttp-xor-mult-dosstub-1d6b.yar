rule TTP_XOR_MULT_DOSStub_1d6b {
  strings:
    $key_1d6b = { 49 03 [2] 3d 1b [2] 7a 19 [2] 3d 08 [2] 73 04 [2] 7f 0e [2] 68 05 [2] 73 4b [2] 4e }

  condition:
    any of them
}