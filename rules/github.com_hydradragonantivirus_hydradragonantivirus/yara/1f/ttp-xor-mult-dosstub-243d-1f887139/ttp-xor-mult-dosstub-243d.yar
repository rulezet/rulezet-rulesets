rule TTP_XOR_MULT_DOSStub_243d {
  strings:
    $key_243d = { 70 55 [2] 04 4d [2] 43 4f [2] 04 5e [2] 4a 52 [2] 46 58 [2] 51 53 [2] 4a 1d [2] 77 }

  condition:
    any of them
}