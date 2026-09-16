rule TTP_XOR_MULT_DOSStub_f94d {
  strings:
    $key_f94d = { ad 25 [2] d9 3d [2] 9e 3f [2] d9 2e [2] 97 22 [2] 9b 28 [2] 8c 23 [2] 97 6d [2] aa }

  condition:
    any of them
}