rule TTP_XOR_MULT_DOSStub_055e {
  strings:
    $key_055e = { 51 36 [2] 25 2e [2] 62 2c [2] 25 3d [2] 6b 31 [2] 67 3b [2] 70 30 [2] 6b 7e [2] 56 }

  condition:
    any of them
}