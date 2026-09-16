rule TTP_XOR_MULT_DOSStub_095d {
  strings:
    $key_095d = { 5d 35 [2] 29 2d [2] 6e 2f [2] 29 3e [2] 67 32 [2] 6b 38 [2] 7c 33 [2] 67 7d [2] 5a }

  condition:
    any of them
}