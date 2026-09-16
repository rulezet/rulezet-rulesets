rule TTP_XOR_MULT_DOSStub_39ba {
  strings:
    $key_39ba = { 6d d2 [2] 19 ca [2] 5e c8 [2] 19 d9 [2] 57 d5 [2] 5b df [2] 4c d4 [2] 57 9a [2] 6a }

  condition:
    any of them
}