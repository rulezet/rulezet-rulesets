rule TTP_XOR_MULT_DOSStub_f903 {
  strings:
    $key_f903 = { ad 6b [2] d9 73 [2] 9e 71 [2] d9 60 [2] 97 6c [2] 9b 66 [2] 8c 6d [2] 97 23 [2] aa }

  condition:
    any of them
}