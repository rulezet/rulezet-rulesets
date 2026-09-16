rule TTP_XOR_MULT_DOSStub_1d4c {
  strings:
    $key_1d4c = { 49 24 [2] 3d 3c [2] 7a 3e [2] 3d 2f [2] 73 23 [2] 7f 29 [2] 68 22 [2] 73 6c [2] 4e }

  condition:
    any of them
}