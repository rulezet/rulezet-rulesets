rule TTP_XOR_MULT_DOSStub_0deb {
  strings:
    $key_0deb = { 59 83 [2] 2d 9b [2] 6a 99 [2] 2d 88 [2] 63 84 [2] 6f 8e [2] 78 85 [2] 63 cb [2] 5e }

  condition:
    any of them
}