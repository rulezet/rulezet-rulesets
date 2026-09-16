rule TTP_XOR_MULT_DOSStub_f921 {
  strings:
    $key_f921 = { ad 49 [2] d9 51 [2] 9e 53 [2] d9 42 [2] 97 4e [2] 9b 44 [2] 8c 4f [2] 97 01 [2] aa }

  condition:
    any of them
}