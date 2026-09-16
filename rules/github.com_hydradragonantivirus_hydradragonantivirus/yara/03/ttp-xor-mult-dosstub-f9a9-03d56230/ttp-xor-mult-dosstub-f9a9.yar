rule TTP_XOR_MULT_DOSStub_f9a9 {
  strings:
    $key_f9a9 = { ad c1 [2] d9 d9 [2] 9e db [2] d9 ca [2] 97 c6 [2] 9b cc [2] 8c c7 [2] 97 89 [2] aa }

  condition:
    any of them
}