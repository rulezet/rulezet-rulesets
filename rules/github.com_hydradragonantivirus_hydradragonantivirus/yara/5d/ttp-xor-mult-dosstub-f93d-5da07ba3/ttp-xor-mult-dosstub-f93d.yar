rule TTP_XOR_MULT_DOSStub_f93d {
  strings:
    $key_f93d = { ad 55 [2] d9 4d [2] 9e 4f [2] d9 5e [2] 97 52 [2] 9b 58 [2] 8c 53 [2] 97 1d [2] aa }

  condition:
    any of them
}