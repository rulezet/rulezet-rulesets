rule TTP_XOR_MULT_DOSStub_670d {
  strings:
    $key_670d = { 33 65 [2] 47 7d [2] 00 7f [2] 47 6e [2] 09 62 [2] 05 68 [2] 12 63 [2] 09 2d [2] 34 }

  condition:
    any of them
}