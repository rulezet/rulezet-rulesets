rule TTP_XOR_MULT_DOSStub_e9ba {
  strings:
    $key_e9ba = { bd d2 [2] c9 ca [2] 8e c8 [2] c9 d9 [2] 87 d5 [2] 8b df [2] 9c d4 [2] 87 9a [2] ba }

  condition:
    any of them
}