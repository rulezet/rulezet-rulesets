rule TTP_XOR_MULT_DOSStub_f9e3 {
  strings:
    $key_f9e3 = { ad 8b [2] d9 93 [2] 9e 91 [2] d9 80 [2] 97 8c [2] 9b 86 [2] 8c 8d [2] 97 c3 [2] aa }

  condition:
    any of them
}