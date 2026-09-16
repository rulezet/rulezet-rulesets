rule TTP_XOR_MULT_DOSStub_f40c {
  strings:
    $key_f40c = { a0 64 [2] d4 7c [2] 93 7e [2] d4 6f [2] 9a 63 [2] 96 69 [2] 81 62 [2] 9a 2c [2] a7 }

  condition:
    any of them
}