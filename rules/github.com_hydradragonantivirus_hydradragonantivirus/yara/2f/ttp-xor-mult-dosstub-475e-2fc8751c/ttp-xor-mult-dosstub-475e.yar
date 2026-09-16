rule TTP_XOR_MULT_DOSStub_475e {
  strings:
    $key_475e = { 13 36 [2] 67 2e [2] 20 2c [2] 67 3d [2] 29 31 [2] 25 3b [2] 32 30 [2] 29 7e [2] 14 }

  condition:
    any of them
}