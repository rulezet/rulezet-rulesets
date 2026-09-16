rule TTP_XOR_MULT_DOSStub_4b5e {
  strings:
    $key_4b5e = { 1f 36 [2] 6b 2e [2] 2c 2c [2] 6b 3d [2] 25 31 [2] 29 3b [2] 3e 30 [2] 25 7e [2] 18 }

  condition:
    any of them
}