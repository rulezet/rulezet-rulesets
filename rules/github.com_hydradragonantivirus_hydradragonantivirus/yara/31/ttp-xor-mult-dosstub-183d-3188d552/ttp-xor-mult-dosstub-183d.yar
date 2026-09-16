rule TTP_XOR_MULT_DOSStub_183d {
  strings:
    $key_183d = { 4c 55 [2] 38 4d [2] 7f 4f [2] 38 5e [2] 76 52 [2] 7a 58 [2] 6d 53 [2] 76 1d [2] 4b }

  condition:
    any of them
}