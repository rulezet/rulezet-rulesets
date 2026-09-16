rule TTP_XOR_MULT_DOSStub_f508 {
  strings:
    $key_f508 = { a1 60 [2] d5 78 [2] 92 7a [2] d5 6b [2] 9b 67 [2] 97 6d [2] 80 66 [2] 9b 28 [2] a6 }

  condition:
    any of them
}