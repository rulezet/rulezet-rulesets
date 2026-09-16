rule TTP_XOR_MULT_DOSStub_29ba {
  strings:
    $key_29ba = { 7d d2 [2] 09 ca [2] 4e c8 [2] 09 d9 [2] 47 d5 [2] 4b df [2] 5c d4 [2] 47 9a [2] 7a }

  condition:
    any of them
}