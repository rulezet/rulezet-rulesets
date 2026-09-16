rule TTP_XOR_MULT_DOSStub_467d {
  strings:
    $key_467d = { 12 15 [2] 66 0d [2] 21 0f [2] 66 1e [2] 28 12 [2] 24 18 [2] 33 13 [2] 28 5d [2] 15 }

  condition:
    any of them
}