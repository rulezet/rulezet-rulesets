rule TTP_XOR_MULT_DOSStub_f37c {
  strings:
    $key_f37c = { a7 14 [2] d3 0c [2] 94 0e [2] d3 1f [2] 9d 13 [2] 91 19 [2] 86 12 [2] 9d 5c [2] a0 }

  condition:
    any of them
}