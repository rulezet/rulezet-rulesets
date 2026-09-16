rule TTP_XOR_MULT_DOSStub_015e {
  strings:
    $key_015e = { 55 36 [2] 21 2e [2] 66 2c [2] 21 3d [2] 6f 31 [2] 63 3b [2] 74 30 [2] 6f 7e [2] 52 }

  condition:
    any of them
}