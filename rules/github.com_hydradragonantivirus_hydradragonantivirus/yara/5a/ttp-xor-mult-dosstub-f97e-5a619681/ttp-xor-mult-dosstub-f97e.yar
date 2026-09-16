rule TTP_XOR_MULT_DOSStub_f97e {
  strings:
    $key_f97e = { ad 16 [2] d9 0e [2] 9e 0c [2] d9 1d [2] 97 11 [2] 9b 1b [2] 8c 10 [2] 97 5e [2] aa }

  condition:
    any of them
}