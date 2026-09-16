rule TTP_XOR_MULT_DOSStub_070d {
  strings:
    $key_070d = { 53 65 [2] 27 7d [2] 60 7f [2] 27 6e [2] 69 62 [2] 65 68 [2] 72 63 [2] 69 2d [2] 54 }

  condition:
    any of them
}