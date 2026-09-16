rule TTP_XOR_MULT_DOSStub_6a5e {
  strings:
    $key_6a5e = { 3e 36 [2] 4a 2e [2] 0d 2c [2] 4a 3d [2] 04 31 [2] 08 3b [2] 1f 30 [2] 04 7e [2] 39 }

  condition:
    any of them
}