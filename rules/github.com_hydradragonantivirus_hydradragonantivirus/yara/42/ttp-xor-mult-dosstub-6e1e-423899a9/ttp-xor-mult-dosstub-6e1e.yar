rule TTP_XOR_MULT_DOSStub_6e1e {
  strings:
    $key_6e1e = { 3a 76 [2] 4e 6e [2] 09 6c [2] 4e 7d [2] 00 71 [2] 0c 7b [2] 1b 70 [2] 00 3e [2] 3d }

  condition:
    any of them
}