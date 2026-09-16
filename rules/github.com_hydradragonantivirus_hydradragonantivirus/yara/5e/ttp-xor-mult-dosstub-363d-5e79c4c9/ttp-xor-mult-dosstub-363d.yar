rule TTP_XOR_MULT_DOSStub_363d {
  strings:
    $key_363d = { 62 55 [2] 16 4d [2] 51 4f [2] 16 5e [2] 58 52 [2] 54 58 [2] 43 53 [2] 58 1d [2] 65 }

  condition:
    any of them
}