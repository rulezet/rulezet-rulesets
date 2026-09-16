rule TTP_XOR_MULT_DOSStub_f922 {
  strings:
    $key_f922 = { ad 4a [2] d9 52 [2] 9e 50 [2] d9 41 [2] 97 4d [2] 9b 47 [2] 8c 4c [2] 97 02 [2] aa }

  condition:
    any of them
}