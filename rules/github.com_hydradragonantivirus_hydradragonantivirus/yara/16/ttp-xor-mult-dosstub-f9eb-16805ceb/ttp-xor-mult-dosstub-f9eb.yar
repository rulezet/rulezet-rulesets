rule TTP_XOR_MULT_DOSStub_f9eb {
  strings:
    $key_f9eb = { ad 83 [2] d9 9b [2] 9e 99 [2] d9 88 [2] 97 84 [2] 9b 8e [2] 8c 85 [2] 97 cb [2] aa }

  condition:
    any of them
}