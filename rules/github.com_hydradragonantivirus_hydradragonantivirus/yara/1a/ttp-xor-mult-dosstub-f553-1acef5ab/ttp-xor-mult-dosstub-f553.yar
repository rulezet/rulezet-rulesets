rule TTP_XOR_MULT_DOSStub_f553 {
  strings:
    $key_f553 = { a1 3b [2] d5 23 [2] 92 21 [2] d5 30 [2] 9b 3c [2] 97 36 [2] 80 3d [2] 9b 73 [2] a6 }

  condition:
    any of them
}