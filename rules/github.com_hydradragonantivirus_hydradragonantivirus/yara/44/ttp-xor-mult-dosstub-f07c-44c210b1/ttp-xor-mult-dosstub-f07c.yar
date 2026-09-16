rule TTP_XOR_MULT_DOSStub_f07c {
  strings:
    $key_f07c = { a4 14 [2] d0 0c [2] 97 0e [2] d0 1f [2] 9e 13 [2] 92 19 [2] 85 12 [2] 9e 5c [2] a3 }

  condition:
    any of them
}