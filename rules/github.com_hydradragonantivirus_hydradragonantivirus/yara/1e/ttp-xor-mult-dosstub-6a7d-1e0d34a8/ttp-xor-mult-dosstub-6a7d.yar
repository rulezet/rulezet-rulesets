rule TTP_XOR_MULT_DOSStub_6a7d {
  strings:
    $key_6a7d = { 3e 15 [2] 4a 0d [2] 0d 0f [2] 4a 1e [2] 04 12 [2] 08 18 [2] 1f 13 [2] 04 5d [2] 39 }

  condition:
    any of them
}