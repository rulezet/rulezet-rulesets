rule TTP_XOR_MULT_DOSStub_1d75 {
  strings:
    $key_1d75 = { 49 1d [2] 3d 05 [2] 7a 07 [2] 3d 16 [2] 73 1a [2] 7f 10 [2] 68 1b [2] 73 55 [2] 4e }

  condition:
    any of them
}