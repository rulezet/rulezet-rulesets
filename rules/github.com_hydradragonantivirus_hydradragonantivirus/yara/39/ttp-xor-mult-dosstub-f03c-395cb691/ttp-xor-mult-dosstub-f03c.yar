rule TTP_XOR_MULT_DOSStub_f03c {
  strings:
    $key_f03c = { a4 54 [2] d0 4c [2] 97 4e [2] d0 5f [2] 9e 53 [2] 92 59 [2] 85 52 [2] 9e 1c [2] a3 }

  condition:
    any of them
}