rule TTP_XOR_MULT_DOSStub_1deb {
  strings:
    $key_1deb = { 49 83 [2] 3d 9b [2] 7a 99 [2] 3d 88 [2] 73 84 [2] 7f 8e [2] 68 85 [2] 73 cb [2] 4e }

  condition:
    any of them
}