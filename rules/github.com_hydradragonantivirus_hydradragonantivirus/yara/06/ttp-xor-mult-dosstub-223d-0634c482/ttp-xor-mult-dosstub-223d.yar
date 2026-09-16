rule TTP_XOR_MULT_DOSStub_223d {
  strings:
    $key_223d = { 76 55 [2] 02 4d [2] 45 4f [2] 02 5e [2] 4c 52 [2] 40 58 [2] 57 53 [2] 4c 1d [2] 71 }

  condition:
    any of them
}