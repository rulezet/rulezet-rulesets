rule TTP_XOR_MULT_DOSStub_297d {
  strings:
    $key_297d = { 7d 15 [2] 09 0d [2] 4e 0f [2] 09 1e [2] 47 12 [2] 4b 18 [2] 5c 13 [2] 47 5d [2] 7a }

  condition:
    any of them
}