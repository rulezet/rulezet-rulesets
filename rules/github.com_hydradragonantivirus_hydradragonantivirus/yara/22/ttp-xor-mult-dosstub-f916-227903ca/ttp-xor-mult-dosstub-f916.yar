rule TTP_XOR_MULT_DOSStub_f916 {
  strings:
    $key_f916 = { ad 7e [2] d9 66 [2] 9e 64 [2] d9 75 [2] 97 79 [2] 9b 73 [2] 8c 78 [2] 97 36 [2] aa }

  condition:
    any of them
}