rule TTP_XOR_MULT_DOSStub_f961 {
  strings:
    $key_f961 = { ad 09 [2] d9 11 [2] 9e 13 [2] d9 02 [2] 97 0e [2] 9b 04 [2] 8c 0f [2] 97 41 [2] aa }

  condition:
    any of them
}