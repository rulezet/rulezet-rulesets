rule TTP_XOR_MULT_DOSStub_267d {
  strings:
    $key_267d = { 72 15 [2] 06 0d [2] 41 0f [2] 06 1e [2] 48 12 [2] 44 18 [2] 53 13 [2] 48 5d [2] 75 }

  condition:
    any of them
}