rule TTP_XOR_MULT_DOSStub_575e {
  strings:
    $key_575e = { 03 36 [2] 77 2e [2] 30 2c [2] 77 3d [2] 39 31 [2] 35 3b [2] 22 30 [2] 39 7e [2] 04 }

  condition:
    any of them
}