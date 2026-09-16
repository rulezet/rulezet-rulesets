rule TTP_XOR_MULT_DOSStub_362d {
  strings:
    $key_362d = { 62 45 [2] 16 5d [2] 51 5f [2] 16 4e [2] 58 42 [2] 54 48 [2] 43 43 [2] 58 0d [2] 65 }

  condition:
    any of them
}