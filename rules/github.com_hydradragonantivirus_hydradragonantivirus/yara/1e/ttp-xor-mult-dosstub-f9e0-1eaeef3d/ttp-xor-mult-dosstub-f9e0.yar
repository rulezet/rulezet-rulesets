rule TTP_XOR_MULT_DOSStub_f9e0 {
  strings:
    $key_f9e0 = { ad 88 [2] d9 90 [2] 9e 92 [2] d9 83 [2] 97 8f [2] 9b 85 [2] 8c 8e [2] 97 c0 [2] aa }

  condition:
    any of them
}