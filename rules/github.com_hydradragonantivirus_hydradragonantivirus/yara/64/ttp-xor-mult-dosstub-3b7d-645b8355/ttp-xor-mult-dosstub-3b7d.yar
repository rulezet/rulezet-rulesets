rule TTP_XOR_MULT_DOSStub_3b7d {
  strings:
    $key_3b7d = { 6f 15 [2] 1b 0d [2] 5c 0f [2] 1b 1e [2] 55 12 [2] 59 18 [2] 4e 13 [2] 55 5d [2] 68 }

  condition:
    any of them
}