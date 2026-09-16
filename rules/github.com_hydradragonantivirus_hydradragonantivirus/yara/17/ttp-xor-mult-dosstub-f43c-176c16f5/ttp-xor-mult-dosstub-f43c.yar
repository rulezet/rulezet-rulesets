rule TTP_XOR_MULT_DOSStub_f43c {
  strings:
    $key_f43c = { a0 54 [2] d4 4c [2] 93 4e [2] d4 5f [2] 9a 53 [2] 96 59 [2] 81 52 [2] 9a 1c [2] a7 }

  condition:
    any of them
}