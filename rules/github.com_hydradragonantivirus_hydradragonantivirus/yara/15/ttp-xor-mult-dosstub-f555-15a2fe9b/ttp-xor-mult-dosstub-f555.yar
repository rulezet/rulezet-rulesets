rule TTP_XOR_MULT_DOSStub_f555 {
  strings:
    $key_f555 = { a1 3d [2] d5 25 [2] 92 27 [2] d5 36 [2] 9b 3a [2] 97 30 [2] 80 3b [2] 9b 75 [2] a6 }

  condition:
    any of them
}