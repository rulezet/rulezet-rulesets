rule TTP_XOR_MULT_DOSStub_f033 {
  strings:
    $key_f033 = { a4 5b [2] d0 43 [2] 97 41 [2] d0 50 [2] 9e 5c [2] 92 56 [2] 85 5d [2] 9e 13 [2] a3 }

  condition:
    any of them
}