rule TTP_XOR_MULT_DOSStub_f955 {
  strings:
    $key_f955 = { ad 3d [2] d9 25 [2] 9e 27 [2] d9 36 [2] 97 3a [2] 9b 30 [2] 8c 3b [2] 97 75 [2] aa }

  condition:
    any of them
}