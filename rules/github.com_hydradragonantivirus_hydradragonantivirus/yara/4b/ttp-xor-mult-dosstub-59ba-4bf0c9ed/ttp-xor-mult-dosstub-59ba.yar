rule TTP_XOR_MULT_DOSStub_59ba {
  strings:
    $key_59ba = { 0d d2 [2] 79 ca [2] 3e c8 [2] 79 d9 [2] 37 d5 [2] 3b df [2] 2c d4 [2] 37 9a [2] 0a }

  condition:
    any of them
}