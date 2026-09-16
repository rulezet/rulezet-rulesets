rule TTP_XOR_MULT_DOSStub_f75e {
  strings:
    $key_f75e = { a3 36 [2] d7 2e [2] 90 2c [2] d7 3d [2] 99 31 [2] 95 3b [2] 82 30 [2] 99 7e [2] a4 }

  condition:
    any of them
}