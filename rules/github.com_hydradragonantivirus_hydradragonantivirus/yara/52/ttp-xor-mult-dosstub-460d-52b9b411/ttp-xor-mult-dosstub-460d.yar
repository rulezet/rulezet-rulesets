rule TTP_XOR_MULT_DOSStub_460d {
  strings:
    $key_460d = { 12 65 [2] 66 7d [2] 21 7f [2] 66 6e [2] 28 62 [2] 24 68 [2] 33 63 [2] 28 2d [2] 15 }

  condition:
    any of them
}