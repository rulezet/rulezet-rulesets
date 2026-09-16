rule TTP_XOR_MULT_DOSStub_f929 {
  strings:
    $key_f929 = { ad 41 [2] d9 59 [2] 9e 5b [2] d9 4a [2] 97 46 [2] 9b 4c [2] 8c 47 [2] 97 09 [2] aa }

  condition:
    any of them
}