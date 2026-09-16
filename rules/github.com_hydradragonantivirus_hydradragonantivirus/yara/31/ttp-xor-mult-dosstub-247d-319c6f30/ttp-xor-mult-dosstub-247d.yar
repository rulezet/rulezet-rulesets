rule TTP_XOR_MULT_DOSStub_247d {
  strings:
    $key_247d = { 70 15 [2] 04 0d [2] 43 0f [2] 04 1e [2] 4a 12 [2] 46 18 [2] 51 13 [2] 4a 5d [2] 77 }

  condition:
    any of them
}