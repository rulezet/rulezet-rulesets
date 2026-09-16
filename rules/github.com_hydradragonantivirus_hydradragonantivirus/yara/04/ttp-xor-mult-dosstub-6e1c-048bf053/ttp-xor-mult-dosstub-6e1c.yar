rule TTP_XOR_MULT_DOSStub_6e1c {
  strings:
    $key_6e1c = { 3a 74 [2] 4e 6c [2] 09 6e [2] 4e 7f [2] 00 73 [2] 0c 79 [2] 1b 72 [2] 00 3c [2] 3d }

  condition:
    any of them
}