rule TTP_XOR_MULT_DOSStub_f92f {
  strings:
    $key_f92f = { ad 47 [2] d9 5f [2] 9e 5d [2] d9 4c [2] 97 40 [2] 9b 4a [2] 8c 41 [2] 97 0f [2] aa }

  condition:
    any of them
}