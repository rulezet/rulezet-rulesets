rule TTP_XOR_MULT_DOSStub_385e {
  strings:
    $key_385e = { 6c 36 [2] 18 2e [2] 5f 2c [2] 18 3d [2] 56 31 [2] 5a 3b [2] 4d 30 [2] 56 7e [2] 6b }

  condition:
    any of them
}