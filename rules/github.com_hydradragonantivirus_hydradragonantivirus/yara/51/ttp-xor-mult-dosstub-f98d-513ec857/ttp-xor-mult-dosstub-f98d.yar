rule TTP_XOR_MULT_DOSStub_f98d {
  strings:
    $key_f98d = { ad e5 [2] d9 fd [2] 9e ff [2] d9 ee [2] 97 e2 [2] 9b e8 [2] 8c e3 [2] 97 ad [2] aa }

  condition:
    any of them
}