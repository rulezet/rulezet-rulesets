rule TTP_XOR_MULT_DOSStub_283d {
  strings:
    $key_283d = { 7c 55 [2] 08 4d [2] 4f 4f [2] 08 5e [2] 46 52 [2] 4a 58 [2] 5d 53 [2] 46 1d [2] 7b }

  condition:
    any of them
}