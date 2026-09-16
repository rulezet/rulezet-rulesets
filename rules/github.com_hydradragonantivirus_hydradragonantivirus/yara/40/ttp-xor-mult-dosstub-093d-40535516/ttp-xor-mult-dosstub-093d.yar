rule TTP_XOR_MULT_DOSStub_093d {
  strings:
    $key_093d = { 5d 55 [2] 29 4d [2] 6e 4f [2] 29 5e [2] 67 52 [2] 6b 58 [2] 7c 53 [2] 67 1d [2] 5a }

  condition:
    any of them
}