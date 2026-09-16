rule TTP_XOR_MULT_DOSStub_1f5e {
  strings:
    $key_1f5e = { 4b 36 [2] 3f 2e [2] 78 2c [2] 3f 3d [2] 71 31 [2] 7d 3b [2] 6a 30 [2] 71 7e [2] 4c }

  condition:
    any of them
}