rule TTP_XOR_MULT_DOSStub_522d {
  strings:
    $key_522d = { 06 45 [2] 72 5d [2] 35 5f [2] 72 4e [2] 3c 42 [2] 30 48 [2] 27 43 [2] 3c 0d [2] 01 }

  condition:
    any of them
}