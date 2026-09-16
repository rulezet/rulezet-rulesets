rule TTP_XOR_MULT_DOSStub_29a9 {
  strings:
    $key_29a9 = { 7d c1 [2] 09 d9 [2] 4e db [2] 09 ca [2] 47 c6 [2] 4b cc [2] 5c c7 [2] 47 89 [2] 7a }

  condition:
    any of them
}