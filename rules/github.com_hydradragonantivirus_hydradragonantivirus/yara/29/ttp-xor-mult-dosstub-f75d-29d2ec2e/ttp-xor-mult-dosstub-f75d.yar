rule TTP_XOR_MULT_DOSStub_f75d {
  strings:
    $key_f75d = { a3 35 [2] d7 2d [2] 90 2f [2] d7 3e [2] 99 32 [2] 95 38 [2] 82 33 [2] 99 7d [2] a4 }

  condition:
    any of them
}