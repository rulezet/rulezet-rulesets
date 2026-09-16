rule TTP_XOR_MULT_DOSStub_323d {
  strings:
    $key_323d = { 66 55 [2] 12 4d [2] 55 4f [2] 12 5e [2] 5c 52 [2] 50 58 [2] 47 53 [2] 5c 1d [2] 61 }

  condition:
    any of them
}