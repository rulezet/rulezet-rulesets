rule TTP_XOR_MULT_DOSStub_f6a4 {
  strings:
    $key_f6a4 = { a2 cc [2] d6 d4 [2] 91 d6 [2] d6 c7 [2] 98 cb [2] 94 c1 [2] 83 ca [2] 98 84 [2] a5 }

  condition:
    any of them
}