rule TTP_XOR_MULT_DOSStub_353d {
  strings:
    $key_353d = { 61 55 [2] 15 4d [2] 52 4f [2] 15 5e [2] 5b 52 [2] 57 58 [2] 40 53 [2] 5b 1d [2] 66 }

  condition:
    any of them
}