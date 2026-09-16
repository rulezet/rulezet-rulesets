rule TTP_XOR_MULT_DOSStub_5873 {
  strings:
    $key_5873 = { 0c 1b [2] 78 03 [2] 3f 01 [2] 78 10 [2] 36 1c [2] 3a 16 [2] 2d 1d [2] 36 53 [2] 0b }

  condition:
    any of them
}