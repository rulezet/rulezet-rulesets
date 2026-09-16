rule TTP_XOR_MULT_DOSStub_f926 {
  strings:
    $key_f926 = { ad 4e [2] d9 56 [2] 9e 54 [2] d9 45 [2] 97 49 [2] 9b 43 [2] 8c 48 [2] 97 06 [2] aa }

  condition:
    any of them
}