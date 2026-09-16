rule TTP_XOR_MULT_DOSStub_3deb {
  strings:
    $key_3deb = { 69 83 [2] 1d 9b [2] 5a 99 [2] 1d 88 [2] 53 84 [2] 5f 8e [2] 48 85 [2] 53 cb [2] 6e }

  condition:
    any of them
}