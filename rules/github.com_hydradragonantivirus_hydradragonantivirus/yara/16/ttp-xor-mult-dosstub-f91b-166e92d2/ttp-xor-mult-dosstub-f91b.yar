rule TTP_XOR_MULT_DOSStub_f91b {
  strings:
    $key_f91b = { ad 73 [2] d9 6b [2] 9e 69 [2] d9 78 [2] 97 74 [2] 9b 7e [2] 8c 75 [2] 97 3b [2] aa }

  condition:
    any of them
}