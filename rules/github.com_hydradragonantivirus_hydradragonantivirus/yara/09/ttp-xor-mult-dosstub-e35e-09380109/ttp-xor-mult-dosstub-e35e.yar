rule TTP_XOR_MULT_DOSStub_e35e {
  strings:
    $key_e35e = { b7 36 [2] c3 2e [2] 84 2c [2] c3 3d [2] 8d 31 [2] 81 3b [2] 96 30 [2] 8d 7e [2] b0 }

  condition:
    any of them
}