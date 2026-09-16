rule TTP_XOR_MULT_DOSStub_f512 {
  strings:
    $key_f512 = { a1 7a [2] d5 62 [2] 92 60 [2] d5 71 [2] 9b 7d [2] 97 77 [2] 80 7c [2] 9b 32 [2] a6 }

  condition:
    any of them
}