rule TTP_XOR_MULT_DOSStub_065e {
  strings:
    $key_065e = { 52 36 [2] 26 2e [2] 61 2c [2] 26 3d [2] 68 31 [2] 64 3b [2] 73 30 [2] 68 7e [2] 55 }

  condition:
    any of them
}