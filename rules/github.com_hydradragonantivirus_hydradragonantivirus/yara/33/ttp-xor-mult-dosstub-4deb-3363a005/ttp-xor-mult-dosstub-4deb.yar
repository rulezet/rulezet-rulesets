rule TTP_XOR_MULT_DOSStub_4deb {
  strings:
    $key_4deb = { 19 83 [2] 6d 9b [2] 2a 99 [2] 6d 88 [2] 23 84 [2] 2f 8e [2] 38 85 [2] 23 cb [2] 1e }

  condition:
    any of them
}