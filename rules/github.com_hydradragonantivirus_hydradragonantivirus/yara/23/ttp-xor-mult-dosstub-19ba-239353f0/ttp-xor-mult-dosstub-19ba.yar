rule TTP_XOR_MULT_DOSStub_19ba {
  strings:
    $key_19ba = { 4d d2 [2] 39 ca [2] 7e c8 [2] 39 d9 [2] 77 d5 [2] 7b df [2] 6c d4 [2] 77 9a [2] 4a }

  condition:
    any of them
}