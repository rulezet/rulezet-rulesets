rule TTP_XOR_MULT_DOSStub_f93a {
  strings:
    $key_f93a = { ad 52 [2] d9 4a [2] 9e 48 [2] d9 59 [2] 97 55 [2] 9b 5f [2] 8c 54 [2] 97 1a [2] aa }

  condition:
    any of them
}