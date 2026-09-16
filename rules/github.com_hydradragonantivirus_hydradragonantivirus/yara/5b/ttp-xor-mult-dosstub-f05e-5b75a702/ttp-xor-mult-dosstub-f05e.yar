rule TTP_XOR_MULT_DOSStub_f05e {
  strings:
    $key_f05e = { a4 36 [2] d0 2e [2] 97 2c [2] d0 3d [2] 9e 31 [2] 92 3b [2] 85 30 [2] 9e 7e [2] a3 }

  condition:
    any of them
}