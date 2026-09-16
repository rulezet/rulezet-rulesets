rule TTP_XOR_MULT_DOSStub_6b5e {
  strings:
    $key_6b5e = { 3f 36 [2] 4b 2e [2] 0c 2c [2] 4b 3d [2] 05 31 [2] 09 3b [2] 1e 30 [2] 05 7e [2] 38 }

  condition:
    any of them
}