rule TTP_XOR_MULT_DOSStub_682d {
  strings:
    $key_682d = { 3c 45 [2] 48 5d [2] 0f 5f [2] 48 4e [2] 06 42 [2] 0a 48 [2] 1d 43 [2] 06 0d [2] 3b }

  condition:
    any of them
}