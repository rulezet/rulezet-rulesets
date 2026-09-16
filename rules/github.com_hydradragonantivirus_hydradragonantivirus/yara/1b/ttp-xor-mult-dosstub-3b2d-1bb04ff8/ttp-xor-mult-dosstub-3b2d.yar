rule TTP_XOR_MULT_DOSStub_3b2d {
  strings:
    $key_3b2d = { 6f 45 [2] 1b 5d [2] 5c 5f [2] 1b 4e [2] 55 42 [2] 59 48 [2] 4e 43 [2] 55 0d [2] 68 }

  condition:
    any of them
}