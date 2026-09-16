rule TTP_XOR_MULT_DOSStub_29a2 {
  strings:
    $key_29a2 = { 7d ca [2] 09 d2 [2] 4e d0 [2] 09 c1 [2] 47 cd [2] 4b c7 [2] 5c cc [2] 47 82 [2] 7a }

  condition:
    any of them
}