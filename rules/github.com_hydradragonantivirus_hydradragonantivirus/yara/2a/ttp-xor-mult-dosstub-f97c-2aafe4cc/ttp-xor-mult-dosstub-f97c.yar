rule TTP_XOR_MULT_DOSStub_f97c {
  strings:
    $key_f97c = { ad 14 [2] d9 0c [2] 9e 0e [2] d9 1f [2] 97 13 [2] 9b 19 [2] 8c 12 [2] 97 5c [2] aa }

  condition:
    any of them
}