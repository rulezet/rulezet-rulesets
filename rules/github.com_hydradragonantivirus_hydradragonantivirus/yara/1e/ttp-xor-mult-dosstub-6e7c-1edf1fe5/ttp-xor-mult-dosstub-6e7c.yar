rule TTP_XOR_MULT_DOSStub_6e7c {
  strings:
    $key_6e7c = { 3a 14 [2] 4e 0c [2] 09 0e [2] 4e 1f [2] 00 13 [2] 0c 19 [2] 1b 12 [2] 00 5c [2] 3d }

  condition:
    any of them
}