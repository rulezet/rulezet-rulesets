rule TTP_XOR_MULT_DOSStub_f6a9 {
  strings:
    $key_f6a9 = { a2 c1 [2] d6 d9 [2] 91 db [2] d6 ca [2] 98 c6 [2] 94 cc [2] 83 c7 [2] 98 89 [2] a5 }

  condition:
    any of them
}