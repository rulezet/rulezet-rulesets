rule TTP_XOR_MULT_DOSStub_f73c {
  strings:
    $key_f73c = { a3 54 [2] d7 4c [2] 90 4e [2] d7 5f [2] 99 53 [2] 95 59 [2] 82 52 [2] 99 1c [2] a4 }

  condition:
    any of them
}