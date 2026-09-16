rule TTP_XOR_MULT_DOSStub_f01b {
  strings:
    $key_f01b = { a4 73 [2] d0 6b [2] 97 69 [2] d0 78 [2] 9e 74 [2] 92 7e [2] 85 75 [2] 9e 3b [2] a3 }

  condition:
    any of them
}