rule TTP_XOR_MULT_DOSStub_6deb {
  strings:
    $key_6deb = { 39 83 [2] 4d 9b [2] 0a 99 [2] 4d 88 [2] 03 84 [2] 0f 8e [2] 18 85 [2] 03 cb [2] 3e }

  condition:
    any of them
}