rule TTP_XOR_MULT_DOSStub_f974 {
  strings:
    $key_f974 = { ad 1c [2] d9 04 [2] 9e 06 [2] d9 17 [2] 97 1b [2] 9b 11 [2] 8c 1a [2] 97 54 [2] aa }

  condition:
    any of them
}