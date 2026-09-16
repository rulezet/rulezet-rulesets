rule TTP_XOR_MULT_DOSStub_f522 {
  strings:
    $key_f522 = { a1 4a [2] d5 52 [2] 92 50 [2] d5 41 [2] 9b 4d [2] 97 47 [2] 80 4c [2] 9b 02 [2] a6 }

  condition:
    any of them
}