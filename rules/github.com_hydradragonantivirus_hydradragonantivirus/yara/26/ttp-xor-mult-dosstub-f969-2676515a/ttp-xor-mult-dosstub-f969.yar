rule TTP_XOR_MULT_DOSStub_f969 {
  strings:
    $key_f969 = { ad 01 [2] d9 19 [2] 9e 1b [2] d9 0a [2] 97 06 [2] 9b 0c [2] 8c 07 [2] 97 49 [2] aa }

  condition:
    any of them
}