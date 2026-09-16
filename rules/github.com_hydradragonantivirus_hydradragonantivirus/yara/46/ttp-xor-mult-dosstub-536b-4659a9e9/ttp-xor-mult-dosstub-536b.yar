rule TTP_XOR_MULT_DOSStub_536b {
  strings:
    $key_536b = { 07 03 [2] 73 1b [2] 34 19 [2] 73 08 [2] 3d 04 [2] 31 0e [2] 26 05 [2] 3d 4b [2] 00 }

  condition:
    any of them
}