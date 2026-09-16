rule TTP_XOR_MULT_DOSStub_5b2d {
  strings:
    $key_5b2d = { 0f 45 [2] 7b 5d [2] 3c 5f [2] 7b 4e [2] 35 42 [2] 39 48 [2] 2e 43 [2] 35 0d [2] 08 }

  condition:
    any of them
}